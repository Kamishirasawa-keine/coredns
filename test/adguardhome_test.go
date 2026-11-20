package main

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/miekg/dns"
)

// Compare DNS response codes and answer data only, not flags or TTLs.
func TestAdGuardHomeBlocking(t *testing.T) {
	bin := os.Getenv("ADGUARDHOME_BIN")
	if bin == "" {
		t.Skip("set ADGUARDHOME_BIN to run against a real AdGuard Home binary")
	}
	upstream := startMockUpstream(t, "192.0.2.1", false, 0)
	const rules = `||ads.example^
@@||allow.ads.example^
||*pcdn*.biliapi.net^$important
@@||except-pcdn.biliapi.net^
@@||allow-pcdn.biliapi.net^$important
||mcdn.bilivideo.com^$important
/^tracker[0-9]+\.example$/
`
	for _, mode := range []struct{ coredns, agh string }{
		{"NXDOMAIN", "nxdomain"}, {"REFUSED", "refused"}, {"ZERO", "null_ip"},
	} {
		t.Run(mode.coredns, func(t *testing.T) {
			dir := t.TempDir()
			write := func(name, data string) string {
				t.Helper()
				p := filepath.Join(dir, name)
				if err := os.WriteFile(p, []byte(data), 0o600); err != nil {
					t.Fatal(err)
				}
				return p
			}
			list := write("block.txt", rules)
			core := &regressionEnv{port: freePort(t)}
			conf := write("Corefile", fmt.Sprintf(`.:%s {
    bind 127.0.0.1
    blocklist %s {
        block_response %s
    }
    splitroute {
        remote udp://%s
    }
}
`, core.port, list, mode.coredns, upstream.addr))
			core.start(t, dir, exec.Command(regressionBin, "-conf", conf))

			aghDir := filepath.Join(dir, "agh")
			if err := os.Mkdir(aghDir, 0o700); err != nil {
				t.Fatal(err)
			}
			agh := &regressionEnv{port: freePort(t)}
			conf = write("AdGuardHome.yaml", fmt.Sprintf(`schema_version: 34
http:
  address: '127.0.0.1:%s'
users: []
dns:
  bind_hosts: ['127.0.0.1']
  port: %s
  upstream_dns: ['%s']
  fallback_dns: []
  bootstrap_dns: ['%s']
  use_private_ptr_resolvers: false
  hostsfile_enabled: false
  cache_enabled: false
  ratelimit: 0
filtering:
  filtering_enabled: true
  protection_enabled: true
  blocking_mode: %s
  filters_update_interval: 0
filters: []
user_rules:
`, freeTCPPort(t), agh.port, upstream.addr, upstream.addr, mode.agh)+yamlRuleLines(rules))
			agh.start(t, aghDir, exec.Command(bin, "--no-check-update", "-c", conf, "-w", aghDir))

			for _, tc := range []struct {
				name    string
				blocked bool
			}{
				{"ads.example", true}, {"sub.ads.example", true}, {"notads.example", false},
				{"allow.ads.example", false}, {"edge-pcdn-7.biliapi.net", true},
				{"except-pcdn.biliapi.net", true}, {"allow-pcdn.biliapi.net", false},
				{"edge-pcdn.biliapi.network", false}, {"mcdn.bilivideo.com", true},
				{"tracker42.example", true}, {"tracker.example", false},
			} {
				t.Run(tc.name, func(t *testing.T) {
					for _, qtype := range []uint16{dns.TypeA, dns.TypeAAAA} {
						q := new(dns.Msg).SetQuestion(dns.Fqdn(tc.name), qtype)
						ask := func(env *regressionEnv) string {
							t.Helper()
							client := dns.Client{Timeout: 2 * time.Second}
							m, _, err := client.Exchange(q.Copy(), "127.0.0.1:"+env.port)
							if err != nil {
								t.Fatal(err)
							}
							return answerSignature(m)
						}
						before := upstream.count(tc.name)
						ours, ref := ask(core), ask(agh)
						if ours != ref {
							t.Errorf("%s CoreDNS=%q, AdGuard Home=%q", dns.TypeToString[qtype], ours, ref)
						}
						if got := upstream.count(tc.name) - before; (tc.blocked && got != 0) || (!tc.blocked && got != 2) {
							t.Errorf("%s blocked=%t: unexpected upstream count %d", dns.TypeToString[qtype], tc.blocked, got)
						}
					}
				})
			}
		})
	}
}

func yamlRuleLines(rules string) string {
	var b strings.Builder
	for _, line := range strings.Split(strings.TrimSpace(rules), "\n") {
		fmt.Fprintf(&b, "  - '%s'\n", strings.ReplaceAll(line, "'", "''"))
	}
	return b.String()
}

func answerSignature(m *dns.Msg) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%d", m.Rcode)
	for _, rr := range m.Answer {
		rr = dns.Copy(rr)
		rr.Header().Ttl = 0
		fmt.Fprintf(&b, "\n%s", rr.String())
	}
	return b.String()
}
