package splitroute

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"time"

	"github.com/coredns/coredns/plugin/pkg/proxy"
	"github.com/coredns/coredns/plugin/pkg/transport"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const (
	defaultUDPPort = "53"
	defaultTLSPort = "853"
)

var (
	upstreamRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "coredns", Subsystem: "splitroute", Name: "upstream_requests_total",
		Help: "DNS query attempts sent to each configured upstream, excluding health checks.",
	}, []string{"group", "upstream"})
	upstreamDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: "coredns", Subsystem: "splitroute", Name: "upstream_duration_seconds",
		Help: "Elapsed upstream exchange time, including failures but excluding cancellations.",
	}, []string{"group", "upstream"})
	upstreamFailures = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "coredns", Subsystem: "splitroute", Name: "upstream_failures_total",
		Help: "Upstream exchange errors and ignored, SERVFAIL or REFUSED answers, excluding cancellations.",
	}, []string{"group", "upstream"})
)

// upstream is one configured nameserver: a pooled connection holder plus the
// per-exchange options that pin it to a transport.
type upstream struct {
	proxy       *proxy.Proxy
	bootstrap   *bootstrapProxy
	pipeline    *dotPipeline
	viaExchange func(context.Context, *dns.Msg) (*dns.Msg, error)
	opts        proxy.Options
	httpClient  *http.Client
	h3          *http3.Transport
	spec        string // original "scheme://host:port", for logs and metrics
}

// group is a set of upstreams that answer together.
type group struct {
	name       string // "local" or "remote"
	upstreams  []*upstream
	concurrent int
	timeout    time.Duration
	ignore     map[int]struct{}
	ecs4, ecs6 *ecsPrefix

	rr uint32 // rotation counter, keeps the fan-out fair
}

func (g *group) ignored(rcode int) bool {
	_, ok := g.ignore[rcode]
	return ok
}

func (g *group) start(hcInterval time.Duration) {
	for _, u := range g.upstreams {
		upstreamRequests.WithLabelValues(g.name, u.spec)
		upstreamDuration.WithLabelValues(g.name, u.spec)
		upstreamFailures.WithLabelValues(g.name, u.spec)
		u.proxy.Start(hcInterval)
	}
}

func (g *group) stop() {
	for _, u := range g.upstreams {
		u.proxy.Stop()
		if u.pipeline != nil {
			u.pipeline.stop()
		}
		if u.bootstrap != nil {
			u.bootstrap.stop()
		}
		if u.h3 != nil {
			_ = u.h3.Close()
		} else if u.httpClient != nil {
			u.httpClient.CloseIdleConnections()
		}
	}
}

// exchange asks up to concurrent upstreams in parallel and returns the first
// usable answer. rcodes listed in ignore-rcode are treated like a failed
// query (mosdns' drop_resp), so the caller can fall back to the other group.
func (g *group) exchange(ctx context.Context, state request.Request) (*dns.Msg, error) {
	if g == nil || len(g.upstreams) == 0 {
		return nil, errors.New("no upstream configured")
	}

	n := g.concurrent
	if n <= 0 || n > len(g.upstreams) {
		n = len(g.upstreams)
	}

	cctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		msg *dns.Msg
		err error
	}
	ch := make(chan result, n)

	configuredECS := g.ecs4 != nil || g.ecs6 != nil
	var ecs *dns.EDNS0_SUBNET
	if configuredECS {
		ecs = g.queryECS(ctx, state.Req.Question[0].Qtype)
	}
	start := int(atomic.AddUint32(&g.rr, 1) % uint32(len(g.upstreams)))
	for i := 0; i < n; i++ {
		u := g.upstreams[(start+i)%len(g.upstreams)]
		// Every branch needs its own copy of the query: proxy.Connect rewrites
		// the message id in place and would otherwise race with its siblings.
		req := state.Req.Copy()
		if configuredECS {
			if ecs == nil {
				stripECS(req)
			} else {
				copy := *ecs
				copy.Address = append(net.IP(nil), ecs.Address...)
				addECS(req, &copy)
			}
		}
		st := request.Request{W: state.W, Req: req}
		go func(u *upstream) {
			msg, err := g.exchangeOne(cctx, u, st)
			ch <- result{msg: msg, err: err}
		}(u)
	}

	var lastErr error
	for i := 0; i < n; i++ {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case res := <-ch:
			switch {
			case res.err != nil:
				lastErr = res.err
			case res.msg == nil:
				lastErr = errors.New("upstream returned an empty response")
			case g.ignored(res.msg.Rcode):
				lastErr = fmt.Errorf("upstream answered %s, dropped", rcodeName(res.msg.Rcode))
			default:
				if configuredECS {
					stripECS(res.msg)
				}
				return res.msg, nil
			}
		}
	}
	if lastErr == nil {
		lastErr = fmt.Errorf("%s: no upstream answered", g.name)
	}
	return nil, lastErr
}

func (g *group) exchangeOne(ctx context.Context, u *upstream, st request.Request) (*dns.Msg, error) {
	upstreamRequests.WithLabelValues(g.name, u.spec).Inc()
	started := time.Now()
	msg, err := u.exchange(ctx, st)
	if !errors.Is(err, context.Canceled) {
		upstreamDuration.WithLabelValues(g.name, u.spec).Observe(time.Since(started).Seconds())
	}
	if g.upstreamFailed(msg, err) {
		upstreamFailures.WithLabelValues(g.name, u.spec).Inc()
	}
	return msg, err
}

func (u *upstream) exchange(ctx context.Context, st request.Request) (*dns.Msg, error) {
	if u.pipeline != nil {
		return u.pipeline.exchange(ctx, st.Req)
	}
	if u.viaExchange != nil {
		return u.viaExchange(ctx, st.Req)
	}
	p, err := u.queryProxy(ctx)
	if err != nil {
		return nil, err
	}
	msg, _, _, err := p.Connect(ctx, st, u.opts)
	return msg, err
}

func (g *group) upstreamFailed(msg *dns.Msg, err error) bool {
	if err != nil {
		return !errors.Is(err, context.Canceled)
	}
	return msg == nil || g.ignored(msg.Rcode) || msg.Rcode == dns.RcodeServerFailure || msg.Rcode == dns.RcodeRefused
}

func rcodeName(rc int) string {
	if s, ok := dns.RcodeToString[rc]; ok {
		return s
	}
	return fmt.Sprintf("rcode %d", rc)
}

// newUpstream builds one pooled proxy from a "scheme://host[:port]" spec.
func newUpstream(spec string, gname string, timeout time.Duration, serverName string, insecure bool, bootstrap ...string) (*upstream, error) {
	var (
		scheme = "udp"
		host   string
	)

	if i := strings.Index(spec, "://"); i > 0 {
		scheme = strings.ToLower(spec[:i])
		host = spec[i+3:]
	} else {
		host = spec
	}

	var bootstrapAddr string
	if len(bootstrap) > 0 {
		bootstrapAddr = bootstrap[0]
	}
	if scheme == "https" || scheme == "h3" {
		return newDoHUpstream(host, gname, timeout, serverName, insecure, scheme == "h3", bootstrapAddr)
	}

	var (
		proto       string
		defaultPort string
		opts        proxy.Options
	)

	switch scheme {
	case "udp", "dns":
		proto, defaultPort = transport.DNS, defaultUDPPort
		opts.PreferUDP = true
	case "tcp":
		proto, defaultPort = transport.DNS, defaultUDPPort
		opts.ForceTCP = true
	case "tls", "dot":
		proto, defaultPort = transport.TLS, defaultTLSPort
		opts.ForceTCP = true
	case "quic", "doq":
		scheme = "quic"
		proto, defaultPort = transport.QUIC, defaultTLSPort
	default:
		return nil, fmt.Errorf("unsupported upstream scheme %q (use udp://, tcp://, tls://, https://, h3:// or quic://)", scheme)
	}

	addr, err := hostPort(host, defaultPort)
	if err != nil {
		return nil, fmt.Errorf("upstream %q: %w", spec, err)
	}

	p := proxy.NewProxy(gname+"/"+scheme+"://"+addr, addr, proto)
	p.SetReadTimeout(timeout)

	// CoreDNS' proxy selects tcp-tls only when a TLS config is installed,
	// including the default case with system trust and no SNI override.
	if proto == transport.TLS || proto == transport.QUIC {
		cfg := &tls.Config{
			ServerName:         serverName,
			InsecureSkipVerify: insecure,
			MinVersion:         tls.VersionTLS12,
		}
		if proto == transport.QUIC {
			cfg.MinVersion = tls.VersionTLS13
		}
		p.SetTLSConfig(cfg)
	}

	u := &upstream{proxy: p, opts: opts, spec: scheme + "://" + addr}
	if bootstrapAddr != "" {
		name, port, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		if _, err := netip.ParseAddr(name); err != nil {
			if proto != transport.TLS && proto != transport.QUIC {
				return u, nil // Only encrypted upstreams use bootstrap DNS.
			}
			if serverName == "" {
				serverName = name
			}
			u.bootstrap = &bootstrapProxy{resolver: bootstrapResolver(bootstrapAddr), host: name, port: port,
				group: gname, scheme: scheme, timeout: timeout, serverName: serverName, insecure: insecure}
		}
	}
	return u, nil
}

func (u *upstream) enablePipeline(serverName string, insecure bool, bootstrap string, timeout time.Duration) error {
	if u.httpClient != nil {
		return nil
	} // HTTP/2 and HTTP/3 multiplex natively.
	if !strings.HasPrefix(u.spec, "tls://") && !strings.HasPrefix(u.spec, "dot://") {
		return fmt.Errorf("pipeline requires a DoT or DoH upstream: %s", u.spec)
	}
	addr := u.proxy.Addr()
	if serverName == "" {
		serverName, _, _ = net.SplitHostPort(addr)
	}
	u.pipeline = &dotPipeline{addr: addr, timeout: timeout, gate: make(chan struct{}, 1),
		tls: &tls.Config{ServerName: serverName, InsecureSkipVerify: insecure, MinVersion: tls.VersionTLS12}}
	if bootstrap != "" {
		u.pipeline.dialer.Resolver = bootstrapResolver(bootstrap)
	}
	u.bootstrap = nil // the TLS dialer resolves via bootstrap directly
	return nil
}

func newDoHUpstream(host, group string, timeout time.Duration, serverName string, insecure, h3 bool, bootstrap string) (*upstream, error) {
	u, err := url.Parse("https://" + host)
	if err != nil || u.Hostname() == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/dns-query") {
		return nil, fmt.Errorf("invalid DoH endpoint %q: expected https://host[:port][/dns-query]", host)
	}
	addr, err := hostPort(u.Host, "443")
	if err != nil {
		return nil, err
	}
	endpoint := "https://" + addr
	cfg := &tls.Config{ServerName: serverName, InsecureSkipVerify: insecure, MinVersion: tls.VersionTLS12}
	var quicTransport *http3.Transport
	tcpTransport := &http.Transport{
		ForceAttemptHTTP2: true,
		IdleConnTimeout:   90 * time.Second,
		TLSClientConfig:   cfg,
	}
	var tr http.RoundTripper = tcpTransport
	if bootstrap != "" {
		dialer := &net.Dialer{Resolver: bootstrapResolver(bootstrap)}
		tcpTransport.DialContext = dialer.DialContext
	}
	spec := endpoint + "/dns-query"
	if h3 {
		cfg.MinVersion = tls.VersionTLS13
		quicTransport = &http3.Transport{TLSClientConfig: cfg}
		if bootstrap != "" {
			resolver := bootstrapResolver(bootstrap)
			quicTransport.Dial = func(ctx context.Context, address string, tlsConfig *tls.Config, quicConfig *quic.Config) (*quic.Conn, error) {
				return dialBootstrapQUIC(ctx, resolver, address, tlsConfig, quicConfig)
			}
		}
		tr = quicTransport
		spec = "h3://" + addr + "/dns-query"
	}
	client := &http.Client{Transport: tr, Timeout: timeout, CheckRedirect: func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}}
	p := proxy.NewProxy(group+"/"+spec, endpoint, transport.HTTPS)
	// Configure proxy health-check TLS before installing the HTTP/3 transport;
	// Proxy.SetTLSConfig assumes an *http.Transport when a client is present.
	p.SetTLSConfig(cfg)
	p.SetHTTPClient(client)
	p.SetDOHHost(serverName)
	return &upstream{proxy: p, httpClient: client, spec: spec, h3: quicTransport}, nil
}

// hostPort normalises bare IPv4/IPv6 addresses to a dialable host:port pair.
func hostPort(host, defaultPort string) (string, error) {

	host = strings.TrimSpace(host)
	if host == "" {
		return "", errors.New("empty address")
	}

	if strings.HasPrefix(host, "[") {
		if h, p, err := net.SplitHostPort(host); err == nil {
			if p == "" {
				p = defaultPort
			}
			return net.JoinHostPort(h, p), nil
		}
		h := strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		return net.JoinHostPort(h, defaultPort), nil
	}

	// Two or more colons and no brackets: a bare IPv6 literal.
	if strings.Count(host, ":") >= 2 {
		return net.JoinHostPort(host, defaultPort), nil
	}

	if h, p, err := net.SplitHostPort(host); err == nil {
		if p == "" {
			p = defaultPort
		}
		return net.JoinHostPort(h, p), nil
	}
	return net.JoinHostPort(host, defaultPort), nil
}
