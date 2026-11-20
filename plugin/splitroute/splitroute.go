// Package splitroute routes queries to different upstream groups based on
// whether the qname belongs to a domain set, with a latency-triggered fallback
// to the secondary group.
//
// It replaces the mosdns pipeline
//
//	qname $cn_domains -> $local_fallback (fallback local -> remote, threshold 500)
//	otherwise         -> $forward_remote
//
// CoreDNS' built-in forward plugin can only hold one set of upstreams per
// server block, and cannot express "answer from the domestic resolvers, but
// hand over to the overseas ones when they are slow or fail", so the routing
// and the fallback both live here.
package splitroute

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/coredns/caddy"
	"github.com/coredns/coredns/plugin"
	"github.com/coredns/coredns/plugin/pkg/log"
	"github.com/coredns/coredns/request"
	"github.com/miekg/dns"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"

	"simplifiedns.local/core/plugin/domainlist"
)

const pluginName = "splitroute"

var clog = log.NewWithPlugin(pluginName)

var (
	queriesTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "coredns",
		Subsystem: pluginName,
		Name:      "queries_total",
		Help:      "Queries per routing decision.",
	}, []string{"route"})

	fallbackTotal = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: "coredns",
		Subsystem: pluginName,
		Name:      "fallback_total",
		Help:      "Queries where the secondary upstream group was started before the primary answered.",
	})

	fallbackAnswers = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "coredns", Subsystem: pluginName, Name: "fallback_answers_total",
		Help: "Replies returned from the opposite upstream group instead of the selected group.",
	}, []string{"group"})

	failuresTotal = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: "coredns",
		Subsystem: pluginName,
		Name:      "failures_total",
		Help:      "Queries that got no usable answer, per group.",
	}, []string{"group"})

	rulesGauge = promauto.NewGauge(prometheus.GaugeOpts{
		Namespace: "coredns",
		Subsystem: pluginName,
		Name:      "rules",
		Help:      "Number of domain-split rules currently loaded.",
	})
)

func init() {
	caddy.RegisterPlugin(pluginName, caddy.Plugin{ServerType: "dns", Action: setup})
}

// SplitRoute is the plugin handler.
type SplitRoute struct {
	Next plugin.Handler

	rules  *domainlist.FileSet
	mode   string // empty preserves legacy local-to-remote fallback
	local  *group // primary, used for qnames inside the set
	remote *group // secondary and default route

	// threshold is how long the local group may stay silent before the remote
	// group is started in parallel. < 0 disables the fallback entirely.
	threshold time.Duration

	hcInterval time.Duration

	stop chan struct{}
	once sync.Once
}

// Name implements plugin.Handler.
func (s *SplitRoute) Name() string { return pluginName }

// ServeDNS implements plugin.Handler.
func (s *SplitRoute) ServeDNS(ctx context.Context, w dns.ResponseWriter, r *dns.Msg) (int, error) {
	if r.Opcode != dns.OpcodeQuery || len(r.Question) != 1 {
		return s.fail(w, r, dns.RcodeFormatError, "",
			errors.New("only single-question standard queries are supported"))
	}

	state := request.Request{W: w, Req: r}

	var (
		resp     *dns.Msg
		err      error
		fallback bool
		selected = "remote"
	)
	matched := s.rules != nil && s.rules.Match(r.Question[0].Name)
	useLocal := s.local != nil && matched
	if s.mode == "local_first" {
		useLocal = !matched
	}
	if useLocal {
		selected = "local"
		queriesTotal.WithLabelValues(selected).Inc()
		if s.mode == "" {
			resp, fallback, err = s.legacyFallback(ctx, state)
		} else {
			resp, err = s.local.exchange(ctx, state)
		}
	} else {
		queriesTotal.WithLabelValues("remote").Inc()
		if s.remote == nil {
			return s.fail(w, r, dns.RcodeServerFailure, "remote",
				errors.New("no remote upstream configured"))
		}
		resp, err = s.remote.exchange(ctx, state)
	}
	if err != nil || resp == nil {
		if err == nil {
			err = errors.New("empty response")
		}
		return s.fail(w, r, dns.RcodeServerFailure, "", err)
	}

	if resp.Id != r.Id {
		resp.Id = r.Id
	}
	// Keep UDP clients inside their advertised buffer size; the truncation
	// flag makes them retry over TCP, exactly like forward does.
	if state.Proto() == "udp" {
		state.SizeAndDo(resp)
		resp.Truncate(state.Size())
	}
	if fallback {
		// CoreDNS cache.Write deliberately forwards wire replies without storing them,
		// and suppresses writes during prefetch. TTL=0 would not bypass cache min-TTL.
		if !r.AuthenticatedData && (r.IsEdns0() == nil || !r.IsEdns0().Do()) {
			resp.AuthenticatedData = false
		}
		wire, err := resp.Pack()
		if err == nil {
			_, err = w.Write(wire)
		}
		if err != nil {
			return dns.RcodeServerFailure, plugin.Error(pluginName, err)
		}
		fallbackAnswers.WithLabelValues(selected).Inc()
		return resp.Rcode, nil
	}
	if err := w.WriteMsg(resp); err != nil {
		return dns.RcodeServerFailure, plugin.Error(pluginName, err)
	}
	return resp.Rcode, nil
}

// primaryWithFallback queries the local group first and starts the remote
// group when the local one is silent, broken or answered with a dropped rcode.
func (s *SplitRoute) primaryWithFallback(ctx context.Context, state request.Request) (*dns.Msg, error) {
	m, _, err := s.legacyFallback(ctx, state)
	return m, err
}

func (s *SplitRoute) legacyFallback(ctx context.Context, state request.Request) (*dns.Msg, bool, error) {
	if s.remote == nil || s.threshold < 0 {
		m, err := s.local.exchange(ctx, state)
		return m, false, err
	}

	cctx, cancel := context.WithCancel(ctx)
	defer cancel()

	type result struct {
		msg      *dns.Msg
		err      error
		fallback bool
	}
	ch := make(chan result, 2)

	pending := 1
	go func() {
		m, err := s.local.exchange(cctx, state)
		ch <- result{msg: m, err: err}
	}()

	secondaryStarted := false
	startSecondary := func() {
		if secondaryStarted {
			return
		}
		secondaryStarted = true
		pending++
		fallbackTotal.Inc()
		go func() {
			m, err := s.remote.exchange(cctx, state)
			ch <- result{msg: m, err: err, fallback: true}
		}()
	}

	var (
		timer  *time.Timer
		timerC <-chan time.Time
	)
	if s.threshold > 0 {
		timer = time.NewTimer(s.threshold)
		timerC = timer.C
		defer timer.Stop()
	} else {
		// Legacy fallback 0s starts both groups immediately.
		startSecondary()
	}

	var firstErr error
	for {
		select {
		case <-ctx.Done():
			return nil, false, ctx.Err()

		case <-timerC:
			timerC = nil
			startSecondary()

		case res := <-ch:
			pending--
			if res.err == nil && res.msg != nil {
				return res.msg, res.fallback, nil
			}
			if firstErr == nil {
				if res.err != nil {
					firstErr = res.err
				} else {
					firstErr = errors.New("empty response")
				}
			}
			// The primary group is out of options: do not burn the rest of
			// the threshold waiting for a timer.
			startSecondary()
			if pending == 0 {
				return nil, false, firstErr
			}
		}
	}
}

// fail writes an error response and returns the rcode for the log plugin.
// groupName, when not empty, is counted in the failure metric.
func (s *SplitRoute) fail(w dns.ResponseWriter, r *dns.Msg, rcode int, groupName string, err error) (int, error) {
	if groupName != "" {
		failuresTotal.WithLabelValues(groupName).Inc()
	}
	m := new(dns.Msg)
	m.SetRcode(r, rcode)
	m.RecursionAvailable = true
	if opt := r.IsEdns0(); opt != nil {
		m.SetEdns0(opt.UDPSize(), opt.Do())
	}
	if werr := w.WriteMsg(m); werr != nil {
		return dns.RcodeServerFailure, plugin.Error(pluginName, werr)
	}
	return rcode, plugin.Error(pluginName, err)
}

// shutdown stops health checking and the rule file watcher.
func (s *SplitRoute) shutdown() {
	s.once.Do(func() {
		close(s.stop)
		if s.local != nil {
			s.local.stop()
		}
		if s.remote != nil {
			s.remote.stop()
		}
	})
}
