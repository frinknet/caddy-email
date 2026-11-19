package smtp

import (
	"bufio"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"
)

func TestIPLimiterCapsEachIPSeparately(t *testing.T) {
	l := newIPLimiter(2)
	if !l.acquire("10.0.0.1") || !l.acquire("10.0.0.1") {
		t.Fatal("first two connections from one IP must be allowed")
	}
	if l.acquire("10.0.0.1") {
		t.Fatal("third connection from the same IP must be refused")
	}
	if !l.acquire("10.0.0.2") {
		t.Fatal("another IP must keep its own budget")
	}
	l.release("10.0.0.1")
	if !l.acquire("10.0.0.1") {
		t.Fatal("releasing a connection must free a slot for that IP")
	}
}

func TestIPLimiterForgetsIdleIPs(t *testing.T) {
	l := newIPLimiter(1)
	if !l.acquire("10.0.0.1") {
		t.Fatal("first connection must be allowed")
	}
	l.release("10.0.0.1")
	l.mu.Lock()
	n := len(l.conns)
	l.mu.Unlock()
	if n != 0 {
		t.Fatalf("idle IP still tracked: %d entries", n)
	}
}

func TestNewIPLimiterDisabled(t *testing.T) {
	if newIPLimiter(0) != nil {
		t.Fatal("a zero limit must disable the per-IP cap")
	}
}

// TestServeRefusesSecondConnectionFromSameIP drives the listener end to end:
// with a limit of one, a second connection from the same peer must get a
// retryable 421 instead of waiting for a listener-wide slot.
func TestServeRefusesSecondConnectionFromSameIP(t *testing.T) {
	s := &SMTP{
		Listeners: []*ListenerConfig{{
			Port:           0,
			Hostname:       "test",
			MaxConnections: 10,
			MaxIPClients:   1,
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
	if reply := readLine(t, second); !strings.HasPrefix(reply, "421") {
		t.Fatalf("second connection reply = %q, want 421", reply)
	}

	first.Close()
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
			t.Fatal("the IP's slot was never released after the first connection closed")
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func readLine(t *testing.T, conn net.Conn) string {
	t.Helper()
	conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		t.Fatalf("read reply: %v", err)
	}
	return strings.TrimRight(line, "\r\n")
}
