package main

// 端到端回归使用真实 CoreDNS 二进制和本地回环上的模拟上游，不访问公网 DNS。

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/miekg/dns"
	"google.golang.org/protobuf/encoding/protowire"
)

var regressionBin string

func TestMain(m *testing.M) {
	dir, err := os.MkdirTemp("", "coredns-regression-*")
	if err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		os.Exit(1)
	}
	regressionBin = filepath.Join(dir, "coredns")
	out, err := exec.Command("go", "build", "-o", regressionBin, "..").CombinedOutput()
	if err != nil {
		fmt.Fprintf(os.Stderr, "build: %v\n%s\n", err, out)
		_ = os.RemoveAll(dir)
		os.Exit(1)
	}
	code := m.Run()
	_ = os.RemoveAll(dir)
	os.Exit(code)
}

// mockUpstream is a loopback authoritative stub: every A query is answered with
// the server's own address, so tests can tell which group handled the query.
type mockUpstream struct {
	simulateFailures bool

	addr   string
	server *dns.Server
	ip     net.IP

	mu      sync.Mutex
	queries map[string]int
}

func startMockUpstream(t *testing.T, ip string, simulateFailures bool, cacheFanout int) *mockUpstream {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	u := &mockUpstream{addr: pc.LocalAddr().String(), ip: net.ParseIP(ip), queries: map[string]int{}, simulateFailures: simulateFailures}
	cacheReady, staleReady := make(chan struct{}), make(chan struct{})
	u.server = &dns.Server{
		PacketConn: pc,
		Handler: dns.HandlerFunc(func(w dns.ResponseWriter, r *dns.Msg) {
			name := strings.ToLower(strings.TrimSuffix(r.Question[0].Name, "."))
			u.mu.Lock()
			u.queries[name]++
			count := u.queries[name]
			u.mu.Unlock()

			// Hold the first cache probe until the expected fan-out reaches
			// the stub. The resolver cannot cancel the loser before this.
			var gate chan struct{}
			switch name {
			case "cached.foreign.test":
				gate = cacheReady
			case "stale.foreign.test":
				gate = staleReady
			}
			if cacheFanout > 0 && gate != nil {
				if count == cacheFanout {
					close(gate)
				}
				select {
				case <-gate:
				case <-time.After(time.Second):
					return
				}
			}

			m := new(dns.Msg)
			m.SetReply(r)
			m.RecursionAvailable = true
			switch {
			case u.simulateFailures && strings.HasPrefix(name, "servfail."):
				m.Rcode = dns.RcodeServerFailure
			case u.simulateFailures && strings.HasPrefix(name, "negative."):
				m.Rcode = dns.RcodeNameError
			default:
				if u.simulateFailures && strings.HasPrefix(name, "slow.") {
					time.Sleep(900 * time.Millisecond)
				}
				ttl, answer := uint32(60), u.ip
				if name == "stale.foreign.test" {
					if count <= cacheFanout {
						ttl = 1
					} else {
						answer = net.IPv4(198, 51, 100, 2)
					}
				}
				m.Answer = []dns.RR{&dns.A{
					Hdr: dns.RR_Header{Name: r.Question[0].Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: ttl},
					A:   answer,
				}}
			}
			_ = w.WriteMsg(m)
		}),
	}
	go func() { _ = u.server.ActivateAndServe() }()
	t.Cleanup(func() { _ = u.server.Shutdown() })
	return u
}

func (u *mockUpstream) count(name string) int {
	u.mu.Lock()
	defer u.mu.Unlock()
	return u.queries[strings.ToLower(name)]
}

func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := fmt.Sprintf("%d", l.LocalAddr().(*net.UDPAddr).Port)
	_ = l.Close()
	return port
}

func freeTCPPort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := fmt.Sprintf("%d", l.Addr().(*net.TCPAddr).Port)
	_ = l.Close()
	return port
}

type regressionEnv struct {
	local, remote *mockUpstream
	bin           string
	corefile      string
	directList    string
	process       *exec.Cmd
	logFile       string
	port          string
	metricsPort   string
}

func regressionGeoGroup(tag, suffix string) []byte {
	field := func(b []byte, id protowire.Number, value []byte) []byte {
		return protowire.AppendBytes(protowire.AppendTag(b, id, protowire.BytesType), value)
	}
	domain := protowire.AppendVarint(protowire.AppendTag(nil, 1, protowire.VarintType), 2)
	domain = field(domain, 2, []byte(suffix))
	return field(nil, 1, field(field(nil, 1, []byte(tag)), 2, domain))
}

func startCoreDNSForRegression(t *testing.T, fallback time.Duration, concurrent int, mode ...string) *regressionEnv {
	t.Helper()
	dir := t.TempDir()
	env := &regressionEnv{bin: regressionBin}
	env.local = startMockUpstream(t, "192.0.2.1", true, 0)
	env.remote = startMockUpstream(t, "198.51.100.1", false, concurrent)
	// Use the same stub address for each upstream in a group so one counter
	// measures fan-out independently of which duplicated endpoint wins.
	local := strings.TrimSpace(strings.Repeat("udp://"+env.local.addr+" ", concurrent))
	remote := strings.TrimSpace(strings.Repeat("udp://"+env.remote.addr+" ", concurrent))
	env.port = freePort(t)
	env.metricsPort = freeTCPPort(t)

	env.directList = filepath.Join(dir, "direct.txt")
	if err := os.WriteFile(env.directList, []byte("geosite:cn\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	geo := append(regressionGeoGroup("CN", "cn.test"), regressionGeoGroup("HOT", "hot.test")...)
	if err := os.WriteFile(filepath.Join(dir, "geosite.dat"), geo, 0o644); err != nil {
		t.Fatal(err)
	}
	blocked := filepath.Join(dir, "blocked.txt")
	if err := os.WriteFile(blocked, []byte("||ads.test^\n||tracker.cn.test^\n@@||except.ads.test^\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pcdn := filepath.Join(dir, "pcdn.txt")
	if err := os.WriteFile(pcdn, []byte("0.0.0.0 pcdn.test\n0.0.0.0 ADS.test.\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	allow := filepath.Join(dir, "allowlist.txt")
	if err := os.WriteFile(allow, []byte("allow.ads.test\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	env.corefile = filepath.Join(dir, "Corefile")
	routing := "domains " + env.directList
	fanout := strconv.Itoa(concurrent)
	if len(mode) > 1 && mode[1] == "all" {
		fanout = "all"
	}
	if len(mode) > 0 {
		routing = "mode " + mode[0]
		if mode[0] == "default" {
			routing = ""
		}
		for file, tag := range map[string]string{"local.txt": "cn", "remote.txt": "hot"} {
			if err := os.WriteFile(filepath.Join(dir, file), []byte("geosite:"+tag+"\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	conf := fmt.Sprintf(`.:%s {
    bufsize 1232

    blocklist %s %s {
        directory %s
        reload 100ms
        block_response nxdomain
        allowlist %s
    }

    cache {
        success 512 60 1
        denial 512 5 1
        serve_stale 86400s immediate 30s
    }

    splitroute {
        %s
        reload 100ms
        fallback %s

        local %s {
            concurrent %s
            timeout 1s
            ignore-rcode SERVFAIL
        }

        remote %s {
            concurrent %s
            timeout 1s
        }
    }

    prometheus 127.0.0.1:%s
    errors
}
`, env.port, filepath.Base(blocked), filepath.Base(pcdn), dir, filepath.Base(allow), routing, fallback, local, fanout, remote, fanout, env.metricsPort)
	if err := os.WriteFile(env.corefile, []byte(conf), 0o644); err != nil {
		t.Fatal(err)
	}

	env.start(t, dir, exec.Command(env.bin, "-conf", env.corefile))
	return env
}

func (env *regressionEnv) start(t *testing.T, dir string, cmd *exec.Cmd) {
	t.Helper()
	env.logFile = filepath.Join(dir, "resolver.log")
	logF, err := os.Create(env.logFile)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = logF.Close() })
	env.process = cmd
	env.process.Stdout = logF
	env.process.Stderr = logF
	if err := env.process.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = env.process.Process.Kill()
		_ = env.process.Wait()
	})

	// Readiness: the server must answer before the regression cases run.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if m, err := env.query("ready.example.test", "udp"); err == nil && m != nil && m.Rcode == dns.RcodeSuccess {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("%s did not become ready; log:\n%s", cmd.Path, env.logTail())
}

func (e *regressionEnv) logTail() string {
	b, err := os.ReadFile(e.logFile)
	if err != nil {
		return fmt.Sprintf("(read log: %v)", err)
	}
	return string(b)
}

func (e *regressionEnv) query(name, network string) (*dns.Msg, error) {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(name), dns.TypeA)
	var client *dns.Client
	if network == "tcp" {
		client = &dns.Client{Net: "tcp", Timeout: 2 * time.Second}
	} else {
		client = &dns.Client{Net: "udp", Timeout: 2 * time.Second}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resp, _, err := client.ExchangeContext(ctx, m, "127.0.0.1:"+e.port)
	return resp, err
}

func (e *regressionEnv) mustQuery(t *testing.T, name, network string) *dns.Msg {
	t.Helper()
	m, err := e.query(name, network)
	if err != nil {
		t.Fatalf("query %s: %v\nlog:\n%s", name, err, e.logTail())
	}
	return m
}

func (e *regressionEnv) mustAnswerIP(t *testing.T, name, network, want string) *dns.Msg {
	t.Helper()
	m := e.mustQuery(t, name, network)
	if m.Rcode != dns.RcodeSuccess {
		t.Fatalf("%s: rcode=%s, want NOERROR", name, dns.RcodeToString[m.Rcode])
	}
	if len(m.Answer) != 1 {
		t.Fatalf("%s: %d answer records, want 1", name, len(m.Answer))
	}
	a, ok := m.Answer[0].(*dns.A)
	if !ok {
		t.Fatalf("%s: answer type %T", name, m.Answer[0])
	}
	if got := a.A.String(); got != want {
		t.Errorf("%s: answer=%s, want %s", name, got, want)
	}
	return m
}

func (e *regressionEnv) blockMetrics(t *testing.T) (count float64) {
	t.Helper()
	client := http.Client{Timeout: time.Second}
	r, err := client.Get("http://127.0.0.1:" + e.metricsPort + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer r.Body.Close()
	if r.StatusCode != http.StatusOK {
		t.Fatalf("metrics returned %s", r.Status)
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(body), "\n") {
		if !strings.HasPrefix(line, "coredns_blocklist_block_count_total{") {
			continue
		}
		fields := strings.Fields(line)
		value, err := strconv.ParseFloat(fields[len(fields)-1], 64)
		if err != nil {
			t.Fatal(err)
		}
		count += value
	}
	return count
}

func TestRoutingModes(t *testing.T) {
	for _, tc := range []struct{ mode, matched, unmatched string }{
		{"default", "192.0.2.1", "198.51.100.1"},
		{"remote_first", "192.0.2.1", "198.51.100.1"},
		{"local_first", "192.0.2.1", "192.0.2.1"},
	} {
		t.Run(tc.mode, func(t *testing.T) {
			env := startCoreDNSForRegression(t, 0, 1, tc.mode)
			env.mustAnswerIP(t, "matched.cn.test", "udp", tc.matched)
			env.mustAnswerIP(t, "unmatched.other.test", "udp", tc.unmatched)
			env.mustAnswerIP(t, "exception.hot.test", "udp", "198.51.100.1")
			if tc.mode == "remote_first" {
				m := env.mustQuery(t, "servfail.cn.test", "udp")
				if m.Rcode != dns.RcodeServerFailure || env.remote.count("servfail.cn.test") != 0 {
					t.Fatal("explicit mode must not fall back to the other group")
				}
			}
		})
	}
}

func TestBlocklistHotReload(t *testing.T) {
	env := startCoreDNSForRegression(t, 50*time.Millisecond, 1)
	name := "tracker.ads.test"
	if got := env.mustQuery(t, name, "udp").Rcode; got != dns.RcodeNameError {
		t.Fatalf("initial block rcode %d", got)
	}
	path := filepath.Join(filepath.Dir(env.corefile), "allowlist.txt")
	if err := os.WriteFile(path+".new", []byte(name+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path+".new", path); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if env.mustQuery(t, name, "udp").Rcode == dns.RcodeSuccess {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("allowlist update did not take effect")
}

func TestConcurrentAll(t *testing.T) {
	env := startCoreDNSForRegression(t, 50*time.Millisecond, 3, "remote_first", "all")
	// The mock waits for all three upstream requests before answering.
	name := "cached.foreign.test"
	env.mustAnswerIP(t, name, "udp", "198.51.100.1")
	if got := env.remote.count(name); got != 3 {
		t.Fatalf("concurrent all sent %d queries, want 3", got)
	}
	if got := env.local.count(name); got != 0 {
		t.Fatalf("concurrent all queried the opposite group %d times", got)
	}
}

func TestRegressionDNSRouting(t *testing.T) {
	env := startCoreDNSForRegression(t, 50*time.Millisecond, 1)

	t.Run("cn_domains routes to local group", func(t *testing.T) {
		env.mustAnswerIP(t, "www.cn.test", "udp", "192.0.2.1")
		if env.local.count("www.cn.test") != 1 {
			t.Errorf("local upstream count=%d, want 1", env.local.count("www.cn.test"))
		}
	})

	t.Run("everything else routes to remote group", func(t *testing.T) {
		env.mustAnswerIP(t, "www.example.test", "udp", "198.51.100.1")
		if env.local.count("www.example.test") != 0 {
			t.Error("unmatched query must not touch the local group")
		}
	})

	t.Run("ad_domains is rejected with NXDOMAIN", func(t *testing.T) {
		m := env.mustQuery(t, "tracker.ads.test", "udp")
		if m.Rcode != dns.RcodeNameError {
			t.Fatalf("rcode=%s, want NXDOMAIN", dns.RcodeToString[m.Rcode])
		}
		if len(m.Answer) != 0 {
			t.Fatalf("NXDOMAIN must carry no answer section, got %d", len(m.Answer))
		}
	})

	t.Run("blocked queries never reach upstream", func(t *testing.T) {
		before := env.blockMetrics(t)
		name := "blocked-twice.ads.test"
		for i := 0; i < 2; i++ {
			if m := env.mustQuery(t, name, "udp"); m.Rcode != dns.RcodeNameError {
				t.Fatalf("attempt %d: rcode=%s", i, dns.RcodeToString[m.Rcode])
			}
		}
		if got := env.remote.count(name); got != 0 {
			t.Errorf("blocked query reached upstream %d time(s)", got)
		}
		// The response can reach the client just before the counters increment.
		for deadline := time.Now().Add(time.Second); ; {
			delta := env.blockMetrics(t) - before
			if delta == 2 {
				break
			}
			if time.Now().After(deadline) {
				t.Fatalf("blocklist counter delta = %v, want 2", delta)
			}
			time.Sleep(10 * time.Millisecond)
		}
	})

	t.Run("allowlist overrides the blocklist", func(t *testing.T) {
		env.mustAnswerIP(t, "allow.ads.test", "udp", "198.51.100.1")
		env.mustAnswerIP(t, "except.ads.test", "udp", "198.51.100.1")
	})

	t.Run("cache serves repeat queries without upstream traffic", func(t *testing.T) {
		name := "cached.example.test"
		env.mustAnswerIP(t, name, "udp", "198.51.100.1")
		env.mustAnswerIP(t, name, "udp", "198.51.100.1")
		if got := env.remote.count(name); got != 1 {
			t.Errorf("remote upstream count=%d, want 1 (second hit must come from cache)", got)
		}
	})

	t.Run("SERVFAIL from local is dropped and falls back (rcode 2 / drop_resp)", func(t *testing.T) {
		start := time.Now()
		env.mustAnswerIP(t, "servfail.cn.test", "udp", "198.51.100.1")
		if elapsed := time.Since(start); elapsed > 300*time.Millisecond {
			t.Errorf("SERVFAIL fallback took %s", elapsed)
		}
		if env.local.count("servfail.cn.test") != 1 {
			t.Errorf("local upstream count=%d, want 1", env.local.count("servfail.cn.test"))
		}
	})

	t.Run("slow local group loses the race to remote (fallback 500ms)", func(t *testing.T) {
		start := time.Now()
		env.mustAnswerIP(t, "slow.cn.test", "udp", "198.51.100.1")
		if elapsed := time.Since(start); elapsed > 250*time.Millisecond {
			t.Errorf("fallback waited %s for the slow primary", elapsed)
		}
	})

	t.Run("queries are served over TCP as well as UDP", func(t *testing.T) {
		env.mustAnswerIP(t, "tcp.cn.test", "tcp", "192.0.2.1")
	})

	t.Run("split list hot reload needs no restart", func(t *testing.T) {
		before := "fresh.hot.test"
		env.mustAnswerIP(t, before, "udp", "198.51.100.1")

		f, err := os.OpenFile(env.directList, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.WriteString("geosite:hot\n"); err != nil {
			t.Fatal(err)
		}
		_ = f.Close()

		// Use a fresh qname on each attempt so the cache cannot pin the old route.
		var last *dns.Msg
		deadline := time.Now().Add(3 * time.Second)
		for i := 0; time.Now().Before(deadline); i++ {
			m, err := env.query(fmt.Sprintf("after-%d.hot.test", i), "udp")
			last = m
			if err == nil && m.Rcode == dns.RcodeSuccess && len(m.Answer) == 1 {
				if a, ok := m.Answer[0].(*dns.A); ok && a.A.String() == "192.0.2.1" {
					return
				}
			}
			time.Sleep(100 * time.Millisecond)
		}
		t.Fatalf("list change was not picked up; last response: %v; log:\n%s", last, env.logTail())
	})
}
