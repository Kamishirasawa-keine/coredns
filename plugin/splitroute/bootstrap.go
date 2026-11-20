package splitroute

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"time"

	"github.com/coredns/coredns/plugin/pkg/proxy"

	"github.com/quic-go/quic-go"
)

// DoT and DoQ use CoreDNS's pooled transports, which have no resolver hook.
// Resolve lazily, then give the pool an IP literal and the original TLS name.
// Keep the selected address for the lifetime of this configuration.
type bootstrapProxy struct {
	resolver                              *net.Resolver
	host, port, group, scheme, serverName string
	timeout                               time.Duration
	insecure                              bool
	mu                                    sync.Mutex
	resolved                              *proxy.Proxy
	stopped                               bool
}

func (u *upstream) queryProxy(ctx context.Context) (*proxy.Proxy, error) {
	if u.bootstrap == nil {
		return u.proxy, nil
	}
	return u.bootstrap.get(ctx)
}

func (b *bootstrapProxy) get(ctx context.Context) (*proxy.Proxy, error) {
	b.mu.Lock()
	if b.stopped || b.resolved != nil {
		p, stopped := b.resolved, b.stopped
		b.mu.Unlock()
		if stopped {
			return nil, errors.New("bootstrap upstream stopped")
		}
		return p, nil
	}
	b.mu.Unlock()
	ctx, cancel := context.WithTimeout(ctx, b.timeout)
	defer cancel()
	ips, err := b.resolver.LookupNetIP(ctx, "ip", b.host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("bootstrap DNS returned no addresses for %s", b.host)
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.stopped {
		return nil, errors.New("bootstrap upstream stopped")
	}
	if b.resolved == nil {
		u, err := newUpstream(b.scheme+"://"+net.JoinHostPort(ips[0].String(), b.port), b.group, b.timeout, b.serverName, b.insecure)
		if err != nil {
			return nil, err
		}
		u.proxy.Start(5 * time.Second)
		b.resolved = u.proxy
	}
	return b.resolved, nil
}

func (b *bootstrapProxy) stop() {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.stopped = true
	if b.resolved != nil {
		b.resolved.Stop()
	}
}

func parseBootstrap(value string) (string, error) {
	if ip, err := netip.ParseAddr(value); err == nil {
		return net.JoinHostPort(ip.String(), "53"), nil
	}
	addr, err := netip.ParseAddrPort(value)
	if err != nil || addr.Port() == 0 {
		return "", fmt.Errorf("expected a literal IP with optional port, got %q", value)
	}
	return addr.String(), nil
}

func bootstrapResolver(addr string) *net.Resolver {
	return &net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
		var d net.Dialer
		return d.DialContext(ctx, network, addr)
	}}
}

func dialBootstrapQUIC(ctx context.Context, resolver *net.Resolver, addr string, tlsCfg *tls.Config, cfg *quic.Config) (*quic.Conn, error) {
	host, port, err := net.SplitHostPort(addr)
	if err != nil {
		return nil, err
	}
	portNumber, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, err
	}
	ips, err := resolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, fmt.Errorf("bootstrap DNS returned no addresses for %s", host)
	}
	// Dial IP literals, preserving the original hostname for TLS verification.
	if tlsCfg.ServerName == "" {
		tlsCfg = tlsCfg.Clone()
		tlsCfg.ServerName = host
	}
	var failures []error
	for _, ip := range ips {
		conn, err := quic.DialAddr(ctx, netip.AddrPortFrom(ip, uint16(portNumber)).String(), tlsCfg, cfg)
		if err == nil {
			return conn, nil
		}
		failures = append(failures, err)
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
	}
	return nil, errors.Join(failures...)
}
