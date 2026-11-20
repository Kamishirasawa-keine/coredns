// Package blocklist implements DNS blocking with the domain rules commonly
// used in AdGuard Home filters. It does not implement browser filter syntax.
package blocklist

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/metrics"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
)

var blocked = promauto.NewCounterVec(prometheus.CounterOpts{
	Namespace: "coredns", Subsystem: "blocklist", Name: "block_count_total",
	Help: "DNS requests blocked by the blocklist plugin.",
}, []string{"server"})

func init() { plugin.Register("blocklist", setup) }

type rules struct {
	domains map[string]struct{}
	regexps map[string]*regexp.Regexp
}

func canonical(name string) string { return strings.ToLower(strings.TrimSuffix(name, ".")) }

func (r *rules) add(line string) bool {
	line = strings.TrimSpace(line)
	if len(line) > 2 && line[0] == '/' && strings.HasSuffix(line, "/") {
		pattern := line[1 : len(line)-1]
		return r.addRegexp(pattern)
	}
	line, _, _ = strings.Cut(line, "#")
	fields := strings.Fields(line)
	if len(fields) == 0 {
		return false
	}
	if len(fields) == 2 && net.ParseIP(fields[0]) != nil {
		fields = fields[1:]
	}
	if len(fields) != 1 {
		return false
	}
	name := fields[0]
	if strings.HasPrefix(name, "||") {
		if !strings.HasSuffix(name, "^") {
			return false
		}
		name = name[2 : len(name)-1]
		if strings.Contains(name, "*") {
			name = canonical(name)
			if len(name) > 253 || !strings.Contains(name, ".") || strings.Trim(name, "*.") == "" || strings.Contains(name, "..") || !wildcardDomain.MatchString(name) {
				return false
			}
			return r.addRegexp(`(?:^|\.)` + strings.ReplaceAll(regexp.QuoteMeta(name), `\*`, `.*`) + `(?:\.|$)`)
		}
	}
	name = canonical(name)
	if name == "" || name == "localhost" || len(name) > 253 || net.ParseIP(name) != nil {
		return false
	}
	for _, label := range strings.Split(name, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, c := range label {
			if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '-' || c == '_') {
				return false
			}
		}
	}
	if r.domains == nil {
		r.domains = make(map[string]struct{})
	}
	r.domains[name] = struct{}{}
	return true
}

var wildcardDomain = regexp.MustCompile(`^[a-z0-9_.*-]+$`)

func (r *rules) addRegexp(pattern string) bool {
	if _, ok := r.regexps[pattern]; ok {
		return true
	}
	re, err := regexp.Compile("(?i)" + pattern)
	if err != nil {
		return false
	}
	if r.regexps == nil {
		r.regexps = make(map[string]*regexp.Regexp)
	}
	r.regexps[pattern] = re
	return true
}

func (r *rules) match(name string) bool {
	for _, re := range r.regexps {
		if re.MatchString(name) {
			return true
		}
	}
	for {
		if _, ok := r.domains[name]; ok {
			return true
		}
		_, tail, ok := strings.Cut(name, ".")
		if !ok {
			return false
		}
		name = tail
	}
}

type filter struct{ deny, allow, importantDeny, importantAllow, explicitAllow rules }

func (f *filter) blocked(name string) bool {
	if f.explicitAllow.match(name) || f.importantAllow.match(name) {
		return false
	}
	return f.importantDeny.match(name) || f.deny.match(name) && !f.allow.match(name)
}

func (f *filter) load(path string, allow bool) (int, error) {
	file, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer file.Close()
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 4096), 256<<10)
	count := 0
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.Contains(line, "##") && !strings.HasPrefix(line, "/") || strings.Contains(line, "#@#") && !strings.HasPrefix(line, "/") {
			continue
		}
		line, exception := strings.CutPrefix(line, "@@")
		if !strings.HasPrefix(line, "/") {
			line, _, _ = strings.Cut(line, "#")
			line = strings.TrimSpace(line)
		}
		line, important := strings.CutSuffix(line, "$important")
		target := &f.deny
		switch {
		case allow:
			target = &f.explicitAllow
		case important && exception:
			target = &f.importantAllow
		case important:
			target = &f.importantDeny
		case exception:
			target = &f.allow
		}
		if target.add(line) {
			count++
		}
	}
	return count, scanner.Err()
}

// CheckFile uses the runtime parser and rejects downloads with no usable rules.
func CheckFile(path string) error {
	count, err := new(filter).load(path, false)
	if err == nil && count == 0 {
		err = fmt.Errorf("no supported DNS rules in %s", path)
	}
	return err
}

type response struct {
	rcode int
	sink  bool
}

func parseResponse(mode string) (response, error) {
	switch strings.ToUpper(mode) {
	case "NXDOMAIN":
		return response{rcode: dns.RcodeNameError}, nil
	case "NODATA":
		return response{rcode: dns.RcodeSuccess}, nil
	case "REFUSED":
		return response{rcode: dns.RcodeRefused}, nil
	case "ZERO":
		return response{rcode: dns.RcodeSuccess, sink: true}, nil
	default:
		return response{}, fmt.Errorf("block_response must be NXDOMAIN, NODATA, REFUSED or ZERO")
	}
}

func (r response) reply(q *dns.Msg) *dns.Msg {
	m := new(dns.Msg).SetRcode(q, r.rcode)
	m.RecursionAvailable = true
	if r.sink {
		question := q.Question[0]
		h := dns.RR_Header{Name: question.Name, Rrtype: question.Qtype, Class: dns.ClassINET}
		switch question.Qtype {
		case dns.TypeA:
			m.Answer = []dns.RR{&dns.A{Hdr: h, A: net.IPv4zero}}
		case dns.TypeAAAA:
			m.Answer = []dns.RR{&dns.AAAA{Hdr: h, AAAA: net.IPv6zero}}
		}
	}
	return m
}

type handler struct {
	next  plugin.Handler
	rules *ruleSet
	response
}

func (h *handler) Name() string { return "blocklist" }

func (h *handler) ServeDNS(ctx context.Context, w dns.ResponseWriter, q *dns.Msg) (int, error) {
	if len(q.Question) == 1 && q.Question[0].Qclass == dns.ClassINET {
		name := canonical(q.Question[0].Name)
		if h.rules.current.Load().blocked(name) {
			blocked.WithLabelValues(metrics.WithServer(ctx)).Inc()
			return dns.RcodeSuccess, w.WriteMsg(h.reply(q))
		}
	}
	return plugin.NextOrFailure(h.Name(), h.next, ctx, w, q)
}

func setup(c *caddy.Controller) error {
	for c.Next() {
		paths := c.RemainingArgs()
		if len(paths) == 0 {
			return plugin.Error("blocklist", c.ArgErr())
		}
		var allow []string
		interval := defaultReload
		root := defaultRuleDir
		mode := response{rcode: dns.RcodeNameError}
		for c.NextBlock() {
			switch c.Val() {
			case "reload":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return plugin.Error("blocklist", c.ArgErr())
				}
				var err error
				interval, err = time.ParseDuration(args[0])
				if err != nil || interval < 0 {
					return plugin.Error("blocklist", c.Errf("invalid reload interval %q", args[0]))
				}
			case "directory":
				args := c.RemainingArgs()
				if len(args) != 1 || !filepath.IsAbs(args[0]) {
					return plugin.Error("blocklist", c.Err("directory requires an absolute path"))
				}
				root = args[0]
			case "allowlist":
				args := c.RemainingArgs()
				if len(args) == 0 {
					return plugin.Error("blocklist", c.ArgErr())
				}
				allow = append(allow, args...)
			case "block_response":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return plugin.Error("blocklist", c.ArgErr())
				}
				var err error
				mode, err = parseResponse(args[0])
				if err != nil {
					return plugin.Error("blocklist", err)
				}
			default:
				return plugin.Error("blocklist", c.Errf("unknown option %q", c.Val()))
			}
		}
		set := new(ruleSet)
		for _, p := range paths {
			set.files = append(set.files, ruleFile{path: resolvePath(root, p)})
		}
		for _, p := range allow {
			set.files = append(set.files, ruleFile{path: resolvePath(root, p), allow: true})
		}
		if err := set.reload(); err != nil {
			return plugin.Error("blocklist", err)
		}
		if interval > 0 {
			stop := make(chan struct{})
			c.OnStartup(func() error { go set.watch(interval, stop); return nil })
			c.OnShutdown(func() error { close(stop); return nil })
		}
		dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
			return &handler{next: next, rules: set, response: mode}
		})
	}
	return nil
}
