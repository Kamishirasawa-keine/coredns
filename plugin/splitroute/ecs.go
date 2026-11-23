package splitroute

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"github.com/miekg/dns"
)

type ecsPrefix struct {
	addr   netip.Addr
	bits   uint8
	family uint16
}

func parseECS(value string, family uint16) (*ecsPrefix, error) {
	address, length, ok := strings.Cut(value, "/")
	max := 32
	if family == 2 {
		max = 128
	}
	bits, err := strconv.Atoi(length)
	if !ok || err != nil || bits < 0 || bits > max {
		return nil, fmt.Errorf("expected IP/length or /length with prefix length 0–%d", max)
	}
	p := &ecsPrefix{bits: uint8(bits), family: family}
	if address != "" {
		ip, err := netip.ParseAddr(address)
		if err != nil || ip.Zone() != "" || ip.Is4In6() || ip.Is4() != (family == 1) {
			return nil, fmt.Errorf("ECS address %q does not match the configured family", address)
		}
		p.addr = netip.PrefixFrom(ip, bits).Masked().Addr()
	}
	return p, nil
}

// Ask the kernel for an outbound source address without sending traffic.
// The proxy endpoint (possibly loopback) must not determine the ECS address.
func routeSource(ctx context.Context, family uint16) netip.Addr {
	network, target := "udp4", "1.1.1.1:53"
	if family == 2 {
		network, target = "udp6", "[2606:4700:4700::1111]:53"
	}
	c, err := (&net.Dialer{}).DialContext(ctx, network, target)
	if err != nil {
		return netip.Addr{}
	}
	defer c.Close()
	addr := c.LocalAddr().(*net.UDPAddr).AddrPort().Addr().Unmap().WithZone("")
	if !addr.IsGlobalUnicast() {
		return netip.Addr{}
	}
	return addr
}

func (g *group) queryECS(ctx context.Context, qtype uint16) *dns.EDNS0_SUBNET {
	first, second := g.ecs4, g.ecs6
	if qtype == dns.TypeAAAA {
		first, second = second, first
	}
	for _, p := range []*ecsPrefix{first, second} {
		if p == nil {
			continue
		}
		addr := p.addr
		if !addr.IsValid() && p.bits == 0 {
			addr = netip.IPv4Unspecified()
			if p.family == 2 {
				addr = netip.IPv6Unspecified()
			}
		}
		if !addr.IsValid() {
			addr = routeSource(ctx, p.family)
		}
		if !addr.IsValid() {
			continue
		}
		addr = netip.PrefixFrom(addr, int(p.bits)).Masked().Addr()
		return &dns.EDNS0_SUBNET{Code: dns.EDNS0SUBNET, Family: p.family, SourceNetmask: p.bits, Address: net.IP(addr.AsSlice())}
	}
	return nil
}

func stripECS(m *dns.Msg) {
	if opt := m.IsEdns0(); opt != nil {
		options := opt.Option[:0]
		for _, o := range opt.Option {
			if o.Option() != dns.EDNS0SUBNET {
				options = append(options, o)
			}
		}
		opt.Option = options
	}
}

func addECS(m *dns.Msg, ecs *dns.EDNS0_SUBNET) {
	stripECS(m)
	if ecs == nil {
		return
	}
	if m.IsEdns0() == nil {
		m.SetEdns0(1232, false)
	}
	opt := m.IsEdns0()
	opt.Option = append(opt.Option, ecs)
}
