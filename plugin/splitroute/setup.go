package splitroute

import (
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/plugin"
	"github.com/miekg/dns"

	"simplifiedns.local/core/plugin/domainlist"
)

const (
	defaultReload     = 10 * time.Minute
	defaultThreshold  = 500 * time.Millisecond
	defaultTimeout    = 2 * time.Second
	defaultHCInterval = 5 * time.Second
	defaultConcurrent = 2
)

func setup(c *caddy.Controller) error {
	s := &SplitRoute{
		threshold:  defaultThreshold,
		hcInterval: defaultHCInterval,
		stop:       make(chan struct{}),
	}

	configDir := filepath.Dir(c.File())
	var (
		files     []string
		bootstrap string
		builders  []func() error
		reload    = defaultReload
	)

	for c.Next() {
		if !c.NextBlock() {
			return plugin.Error(pluginName, c.Err("expected a configuration block"))
		}
		for {
			switch c.Val() {
			case "domains", "files":
				args := c.RemainingArgs()
				if len(args) == 0 {
					return plugin.Error(pluginName, c.ArgErr())
				}
				files = append(files, args...)

			case "mode":
				args := c.RemainingArgs()
				if len(args) != 1 || (args[0] != "local_first" && args[0] != "remote_first") {
					return c.Err("expected mode local_first or mode remote_first")
				}
				s.mode = args[0]
			case "local_domains", "remote_domains":
				return c.Errf("%s was removed; the routing mode selects local.txt or remote.txt automatically", c.Val())

			case "reload":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return plugin.Error(pluginName, c.ArgErr())
				}
				d, err := time.ParseDuration(args[0])
				if err != nil || d < 0 {
					return plugin.Error(pluginName, c.Errf("invalid reload interval %q", args[0]))
				}
				reload = d

			case "fallback":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return plugin.Error(pluginName, c.ArgErr())
				}
				switch args[0] {
				case "never", "off":
					s.threshold = -1
				default:
					d, err := time.ParseDuration(args[0])
					if err != nil || d < 0 {
						return plugin.Error(pluginName, c.Errf("invalid fallback threshold %q", args[0]))
					}
					s.threshold = d
				}

			case "health-check":
				args := c.RemainingArgs()
				if len(args) != 1 {
					return plugin.Error(pluginName, c.ArgErr())
				}
				d, err := time.ParseDuration(args[0])
				if err != nil || d <= 0 {
					return plugin.Error(pluginName, c.Errf("invalid health-check interval %q", args[0]))
				}
				s.hcInterval = d

			case "bootstrap-dns":
				args := c.RemainingArgs()
				if len(args) != 1 || bootstrap != "" {
					return c.ArgErr()
				}
				addr, err := parseBootstrap(args[0])
				if err != nil {
					return c.Errf("invalid bootstrap DNS: %v", err)
				}
				bootstrap = addr
			case "local", "remote":
				name := c.Val()
				args := c.RemainingArgs()
				if len(args) == 0 {
					return plugin.Error(pluginName, c.Errf("%s: at least one upstream is required", name))
				}
				g := &group{
					name:       name,
					concurrent: defaultConcurrent,
					timeout:    defaultTimeout,
					ignore:     map[int]struct{}{},
				}
				build, err := g.parseBlock(c, args)
				if err != nil {
					return plugin.Error(pluginName, err)
				}
				builders = append(builders, func() error { return build(bootstrap) })
				if name == "local" {
					s.local = g
				} else {
					s.remote = g
				}

			default:
				return plugin.Error(pluginName, c.Errf("unknown property %q", c.Val()))
			}
			if !c.NextBlock() {
				break
			}
		}
	}

	for _, build := range builders {
		if err := build(); err != nil {
			return plugin.Error(pluginName, err)
		}
	}
	if s.remote == nil {
		return plugin.Error(pluginName, c.Err("the remote group is required: it is also the default route"))
	}
	root := dnsserver.GetConfig(c).Root
	if s.mode != "" && len(files) != 0 {
		return c.Err("domains is incompatible with an explicit routing mode")
	}
	if len(files) == 0 {
		if s.mode == "" {
			s.mode = "remote_first"
		}
		if s.mode == "local_first" && s.local == nil {
			return c.Err("local_first requires a local group")
		}
		if s.local != nil {
			dir := root
			if dir == "" {
				dir = configDir
			}
			file := "local.txt"
			if s.mode == "local_first" {
				file = "remote.txt"
			}
			files = []string{filepath.Join(dir, file)}
			root = "" // The auto-selected path already includes the root.
		}
	}
	for i, p := range files {
		if !filepath.IsAbs(p) && root != "" {
			files[i] = filepath.Join(root, p)
		}
	}

	if len(files) > 0 {
		s.rules = domainlist.NewFileSet(files, reload, clog.Warningf)
	}

	c.OnStartup(func() error {
		if s.rules != nil {
			set, err := s.rules.Load()
			if err != nil {
				return plugin.Error(pluginName, err)
			}
			rulesGauge.Set(float64(set.Rules()))
			s.rules.OnReload(func(st *domainlist.Set) { rulesGauge.Set(float64(st.Rules())) })
			s.rules.Watch(s.stop)
			clog.Infof("loaded %d split rules from %d file(s), %d line(s) rejected",
				set.Rules(), len(files), set.Rejected())
		}

		for _, g := range []*group{s.local, s.remote} {
			if g == nil {
				continue
			}
			g.start(s.hcInterval)
			addrs := make([]string, 0, len(g.upstreams))
			for _, u := range g.upstreams {
				addrs = append(addrs, u.spec)
			}
			clog.Infof("%s group: %s (concurrent %d, timeout %s, ignore-rcode %s)",
				g.name, strings.Join(addrs, " "), g.concurrent, g.timeout, g.ignoreList())
		}
		if s.local != nil {
			clog.Infof("fallback threshold: %s", s.threshold)
		}
		return nil
	})
	c.OnShutdown(func() error {
		s.shutdown()
		return nil
	})

	dnsserver.GetConfig(c).AddPlugin(func(next plugin.Handler) plugin.Handler {
		s.Next = next
		return s
	})

	return nil
}

// parseBlock builds the upstreams of a group and applies the optional nested
// option block that follows them on the same line:
//
//	local udp://1.1.1.1 udp://1.0.0.1 {
//	    concurrent 2
//	    timeout 2s
//	    ignore-rcode SERVFAIL
//	}
func (g *group) parseBlock(c *caddy.Controller, args []string) (func(string) error, error) {
	var (
		serverName string
		pipeline   bool
		via        string
		insecure   bool
	)

	// The option block, if any, opens on the same line as the upstream list.
	hasBlock := c.NextArg()
	if hasBlock && c.Val() != "{" {
		return nil, c.Errf("unexpected %q, expected \"{\"", c.Val())
	}
	if hasBlock {
		for c.Next() {
			if c.Val() == "}" {
				break
			}
			opt := c.Val()
			oargs := c.RemainingArgs()
			switch opt {
			case "concurrent":
				if len(oargs) != 1 {
					return nil, c.ArgErr()
				}
				if oargs[0] == "all" {
					g.concurrent = len(args)
					break
				}
				n, err := strconv.Atoi(oargs[0])
				if err != nil || n < 1 {
					return nil, c.Errf("invalid concurrent value %q", oargs[0])
				}
				g.concurrent = n
			case "timeout":
				if len(oargs) != 1 {
					return nil, c.ArgErr()
				}
				d, err := time.ParseDuration(oargs[0])
				if err != nil || d <= 0 {
					return nil, c.Errf("invalid timeout %q", oargs[0])
				}
				g.timeout = d
			case "ignore-rcode":
				if len(oargs) != 1 {
					return nil, c.ArgErr()
				}
				for _, name := range strings.Split(oargs[0], ",") {
					rc, ok := dns.StringToRcode[strings.ToUpper(strings.TrimSpace(name))]
					if !ok {
						return nil, c.Errf("unknown rcode %q", name)
					}
					g.ignore[rc] = struct{}{}
				}
			case "ecs4", "ecs6":
				if len(oargs) != 1 {
					return nil, c.ArgErr()
				}
				family, dst := uint16(1), &g.ecs4
				if opt == "ecs6" {
					family, dst = 2, &g.ecs6
				}
				if *dst != nil {
					return nil, c.Errf("duplicate %s option", opt)
				}
				prefix, err := parseECS(oargs[0], family)
				if err != nil {
					return nil, c.Errf("%s: %v", opt, err)
				}
				*dst = prefix
			case "via":
				if via != "" {
					return nil, c.Err("duplicate via option")
				}
				var err error
				via, err = parseVia(oargs)
				if err != nil {
					return nil, c.Err(err.Error())
				}
			case "pipeline":
				if len(oargs) != 0 {
					return nil, c.ArgErr()
				}
				pipeline = true
			case "tls-servername":
				if len(oargs) != 1 {
					return nil, c.ArgErr()
				}
				serverName = oargs[0]
			case "insecure":
				if len(oargs) != 0 {
					return nil, c.ArgErr()
				}
				insecure = true
			default:
				return nil, c.Errf("unknown %s option %q", g.name, opt)
			}
		}
	}

	return func(bootstrap string) error {
		for _, spec := range args {
			u, err := newUpstream(spec, g.name, g.timeout, serverName, insecure, bootstrap)
			if err != nil {
				return err
			}
			if pipeline {
				if err := u.enablePipeline(serverName, insecure, bootstrap, g.timeout); err != nil {
					return err
				}
			}
			if via != "" {
				if err := u.enableVia(via, serverName, insecure, g.timeout); err != nil {
					return err
				}
			}
			g.upstreams = append(g.upstreams, u)
		}
		if g.concurrent > len(g.upstreams) {
			g.concurrent = len(g.upstreams)
		}
		return nil
	}, nil
}

// ignoreList renders the ignored rcodes for the startup log.
func (g *group) ignoreList() string {
	if len(g.ignore) == 0 {
		return "none"
	}
	out := make([]string, 0, len(g.ignore))
	for rc := range g.ignore {
		out = append(out, rcodeName(rc))
	}
	return strings.Join(out, ",")
}
