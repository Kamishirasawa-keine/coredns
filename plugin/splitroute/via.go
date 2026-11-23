package splitroute

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/miekg/dns"
	socks "golang.org/x/net/proxy"
)

func parseVia(args []string) (string, error) {
	if len(args) != 2 || args[0] != "socks5" {
		return "", fmt.Errorf("expected via socks5 IP:port")
	}
	addr, err := netip.ParseAddrPort(args[1])
	if err != nil || addr.Port() == 0 {
		return "", fmt.Errorf("via requires a literal IP and nonzero port")
	}
	return addr.String(), nil
}

func (u *upstream) enableVia(addr, serverName string, insecure bool, timeout time.Duration) error {
	dialer, err := socks.SOCKS5("tcp", addr, nil, &net.Dialer{Timeout: timeout})
	if err != nil {
		return err
	}
	dial := dialer.(socks.ContextDialer).DialContext
	scheme, _, _ := strings.Cut(u.spec, "://")
	switch scheme {
	case "https":
		u.httpClient.Transport.(*http.Transport).DialContext = dial
	case "tcp", "tls", "dot":
		target := u.proxy.Addr()
		if scheme != "tcp" {
			if serverName == "" {
				serverName, _, err = net.SplitHostPort(target)
				if err != nil {
					return err
				}
			}
			cfg := &tls.Config{ServerName: serverName, InsecureSkipVerify: insecure, MinVersion: tls.VersionTLS12}
			connect := dial
			dial = func(ctx context.Context, network, address string) (net.Conn, error) {
				c, err := connect(ctx, network, address)
				if err != nil {
					return nil, err
				}
				secured := tls.Client(c, cfg)
				if err := secured.HandshakeContext(ctx); err != nil {
					_ = c.Close()
					return nil, err
				}
				return secured, nil
			}
		}
		if u.pipeline != nil {
			u.pipeline.dialContext = dial
			return nil
		}
		u.viaExchange = func(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
			ctx, cancel := context.WithTimeout(ctx, timeout)
			defer cancel()
			c, err := dial(ctx, "tcp", target)
			if err != nil {
				return nil, err
			}
			defer c.Close()
			stop := context.AfterFunc(ctx, func() { _ = c.Close() })
			defer stop()
			m, _, err := (&dns.Client{Timeout: timeout}).ExchangeWithConnContext(ctx, q, &dns.Conn{Conn: c})
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			return m, err
		}
	default:
		return fmt.Errorf("via socks5 supports tcp://, tls:// and https:// upstreams; %s requires UDP support", u.spec)
	}
	return nil
}
