package splitroute

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"
)

// dotPipeline has a single reader per TLS connection and serializes only writes.
// Responses are dispatched by their wire ID, not by arrival order.
type dotPipeline struct {
	addr    string
	tls     *tls.Config
	dialer  net.Dialer
	timeout time.Duration
	mu      sync.Mutex
	session *pipelineSession
	stopped bool
	gate    chan struct{}
}

type pipelineResult struct {
	msg *dns.Msg
	err error
}

type pipelineSession struct {
	conn    *dns.Conn
	writes  chan struct{}
	mu      sync.Mutex
	pending map[uint16]chan pipelineResult // nil reserves an ID whose request timed out
	next    uint16
	dead    error
}

func (p *dotPipeline) get(ctx context.Context) (*pipelineSession, error) {
	select {
	case p.gate <- struct{}{}:
		defer func() { <-p.gate }()
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	p.mu.Lock()
	s, stopped := p.session, p.stopped
	p.mu.Unlock()
	if stopped {
		return nil, net.ErrClosed
	}
	if s != nil {
		s.mu.Lock()
		alive := s.dead == nil
		s.mu.Unlock()
		if alive {
			return s, nil
		}
	}
	c, err := (&tls.Dialer{NetDialer: &p.dialer, Config: p.tls}).DialContext(ctx, "tcp", p.addr)
	if err != nil {
		return nil, err
	}
	s = &pipelineSession{conn: &dns.Conn{Conn: c}, writes: make(chan struct{}, 1), pending: make(map[uint16]chan pipelineResult)}
	p.mu.Lock()
	if p.stopped {
		p.mu.Unlock()
		_ = c.Close()
		return nil, net.ErrClosed
	}
	p.session = s
	p.mu.Unlock()
	go s.read()
	return s, nil
}

func (p *dotPipeline) stop() {
	p.mu.Lock()
	p.stopped = true
	s := p.session
	p.mu.Unlock()
	if s != nil {
		s.fail(net.ErrClosed)
	}
}

func (s *pipelineSession) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.dead != nil {
		return
	}
	s.dead = err
	_ = s.conn.Close()
	for _, ch := range s.pending {
		if ch != nil {
			ch <- pipelineResult{err: err}
		}
	}
	clear(s.pending)
}

func (s *pipelineSession) read() {
	for {
		// Bound idle connection lifetime, including peers that stop responding.
		_ = s.conn.SetReadDeadline(time.Now().Add(90 * time.Second))
		msg, err := s.conn.ReadMsg()
		if err != nil {
			s.fail(err)
			return
		}
		s.mu.Lock()
		ch, ok := s.pending[msg.Id]
		if ok {
			delete(s.pending, msg.Id)
		}
		if ch != nil {
			ch <- pipelineResult{msg: msg}
		}
		s.mu.Unlock()
	}
}

func (p *dotPipeline) exchange(ctx context.Context, q *dns.Msg) (*dns.Msg, error) {
	ctx, cancel := context.WithTimeout(ctx, p.timeout)
	defer cancel()
	s, err := p.get(ctx)
	if err != nil {
		return nil, err
	}
	select {
	case s.writes <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := ctx.Err(); err != nil {
		<-s.writes
		return nil, err
	}
	s.mu.Lock()
	if s.dead != nil {
		err := s.dead
		s.mu.Unlock()
		<-s.writes
		return nil, err
	}
	if len(s.pending) == 1<<16 {
		s.mu.Unlock()
		<-s.writes
		err := errors.New("DoT pipeline IDs exhausted")
		s.fail(err)
		return nil, err
	}
	for {
		s.next++
		if _, ok := s.pending[s.next]; !ok {
			break
		}
	}
	id := s.next
	ch := make(chan pipelineResult, 1)
	s.pending[id] = ch
	s.mu.Unlock()
	msg := q.Copy()
	msg.Id = id
	deadline, _ := ctx.Deadline()
	err = s.conn.SetWriteDeadline(deadline)
	if err == nil {
		err = s.conn.WriteMsg(msg)
	}
	<-s.writes
	if err != nil {
		s.fail(err)
		return nil, err
	}
	select {
	case result := <-ch:
		if result.err != nil {
			return nil, result.err
		}
		r := result.msg
		if !r.Response || r.Opcode != q.Opcode || len(r.Question) != 1 || len(q.Question) != 1 || r.Question[0].Qtype != q.Question[0].Qtype || r.Question[0].Qclass != q.Question[0].Qclass || !strings.EqualFold(r.Question[0].Name, q.Question[0].Name) {
			return nil, errors.New("DoT pipeline response does not match query")
		}
		r.Id = q.Id
		return r, nil
	case <-ctx.Done():
		s.mu.Lock()
		if s.pending[id] == ch {
			s.pending[id] = nil
		}
		s.mu.Unlock()
		return nil, ctx.Err()
	}
}
