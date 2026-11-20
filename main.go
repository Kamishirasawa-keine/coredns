// Command coredns builds CoreDNS with split routing, DNS blocking and a
// small set of upstream plugins.
package main

import (
	"fmt"
	"os"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/core/dnsserver"
	"github.com/coredns/coredns/coremain"

	// Stock plugins available to the packaged Corefile.
	_ "github.com/coredns/coredns/plugin/bind"
	_ "github.com/coredns/coredns/plugin/bufsize"
	_ "github.com/coredns/coredns/plugin/cache"
	_ "github.com/coredns/coredns/plugin/errors"
	_ "github.com/coredns/coredns/plugin/log"
	_ "github.com/coredns/coredns/plugin/metrics" // registers the prometheus directive
	_ "github.com/coredns/coredns/plugin/reload"

	"simplifiedns.local/core/plugin/blocklist"
	"simplifiedns.local/core/plugin/domainlist"
	_ "simplifiedns.local/core/plugin/splitroute"
)

// init splices the out of tree plugins into CoreDNS' global directive order.
//
// CoreDNS orders plugins through dnsserver.Directives (a compile time slice in
// an upstream fork). Out of tree plugins therefore have to place themselves:
//
//	errors, log, blocklist, ..., cache, ..., splitroute, forward
//
// blocklist sits above cache so blocked names never enter the cache; splitroute
// takes the place of forward because it *is* the forwarder.
func init() {
	dnsserver.Directives = insertBefore(dnsserver.Directives, "cache", "blocklist")
	dnsserver.Directives = insertBefore(dnsserver.Directives, "forward", "splitroute")
}

func main() {
	if len(os.Args) == 3 && os.Args[1] == "-check-blocklist" {
		if err := blocklist.CheckFile(os.Args[2]); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	if len(os.Args) >= 4 && os.Args[1] == "-check-geosite" {
		for _, rules := range os.Args[3:] {
			if err := domainlist.CheckGeoSite(os.Args[2], rules); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}
		return
	}
	if len(os.Args) == 3 && os.Args[1] == "-check-config" {
		path := os.Args[2]
		data, err := os.ReadFile(path)
		if err == nil {
			err = caddy.ValidateAndExecuteDirectives(caddy.CaddyfileInput{
				Contents: data, Filepath: path, ServerTypeName: "dns",
			}, nil, true)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
		return
	}
	coremain.Run()
}

// insertBefore inserts name in front of anchor. If anchor is absent the name is
// appended, so a future CoreDNS release that renames the anchor degrades to
// "runs last" instead of silently dropping the plugin.
func insertBefore(list []string, anchor, name string) []string {
	for _, s := range list {
		if s == name {
			return list
		}
	}
	for i, s := range list {
		if s == anchor {
			out := make([]string, 0, len(list)+1)
			out = append(out, list[:i]...)
			out = append(out, name)
			out = append(out, list[i:]...)
			return out
		}
	}
	return append(list, name)
}
