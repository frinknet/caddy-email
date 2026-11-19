package smtp

import (
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func TestIPRateLimiterAllowsBurstThenRefills(t *testing.T) {
	start := time.Now()
	l := newIPRateLimiter(2)
	l.now = func() time.Time { return start }
	if !l.allow("10.0.0.1") || !l.allow("10.0.0.1") {
		t.Fatal("a two-per-second bucket must allow a burst of two")
	}
	if l.allow("10.0.0.1") {
		t.Fatal("the third connection in the same instant must be refused")
	}
	start = start.Add(500 * time.Millisecond)
	if !l.allow("10.0.0.1") {
		t.Fatal("half a second must refill one token at two per second")
	}
	if l.allow("10.0.0.1") {
		t.Fatal("the bucket must not hold more than its burst")
	}
}

func TestIPRateLimiterCapsEachIPSeparately(t *testing.T) {
	l := newIPRateLimiter(1)
	if !l.allow("10.0.0.1") {
		t.Fatal("first connection from one IP must be allowed")
	}
	if l.allow("10.0.0.1") {
		t.Fatal("second connection from the same IP must be refused")
	}
	if !l.allow("10.0.0.2") {
		t.Fatal("another IP must keep its own bucket")
	}
}

func TestIPRateLimiterForgetsIdleIPs(t *testing.T) {
	start := time.Now()
	l := newIPRateLimiter(1)
	l.now = func() time.Time { return start }
	if !l.allow("10.0.0.1") {
		t.Fatal("first connection must be allowed")
	}
	l.now = func() time.Time { return start.Add(2 * time.Second) }
	if !l.allow("10.0.0.2") {
		t.Fatal("another IP must be allowed")
	}
	l.mu.Lock()
	_, kept := l.buckets["10.0.0.1"]
	n := len(l.buckets)
	l.mu.Unlock()
	if kept {
		t.Fatal("a peer idle long enough to refill must be forgotten")
	}
	if n != 1 {
		t.Fatalf("tracked buckets = %d, want 1", n)
	}
}

func TestNewIPRateLimiterDisabled(t *testing.T) {
	if newIPRateLimiter(0) != nil {
		t.Fatal("a zero rate must disable the per-IP rate cap")
	}
}

// TestServeRefusesRapidReconnect drives the listener end to end: with a rate
// of one connection per second, the second connection opened right after the
// first must get a retryable 421 instead of a greeting, and the peer must be
// welcome again once the bucket refills.
func TestServeRefusesRapidReconnect(t *testing.T) {
	s := &SMTP{
		Listeners: []*ListenerConfig{{
			Port:           0,
			Hostname:       "test",
			MaxConnections: 10,
			MaxIPClients:   10,
			MaxIPRate:      1,
			DeliverTimeout: caddy.Duration(5 * time.Second),
		}},
		log: zap.NewNop(),
	}
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	defer s.Stop()
	addr := net.JoinHostPort("127.0.0.1", strconv.Itoa(portOf(t, s.lns[0].Addr())))

	first, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial first: %v", err)
	}
	defer first.Close()
	if greeting := readLine(t, first); !strings.HasPrefix(greeting, "220") {
		t.Fatalf("first connection greeting = %q, want 220", greeting)
	}

	second, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatalf("dial second: %v", err)
	}
	defer second.Close()
	if reply := readLine(t, second); !strings.HasPrefix(reply, "421 4.7.1") {
		t.Fatalf("rapid second connection reply = %q, want 421 4.7.1", reply)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		conn, err := net.Dial("tcp", addr)
		if err == nil {
			greeting := readLine(t, conn)
			conn.Close()
			if strings.HasPrefix(greeting, "220") {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatal("the peer was never allowed back after the bucket refilled")
		}
		time.Sleep(100 * time.Millisecond)
	}
}
