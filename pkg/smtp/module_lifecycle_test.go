package smtp

import (
	"net"
	"strconv"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func portOf(t *testing.T, addr net.Addr) int {
	t.Helper()
	_, p, err := net.SplitHostPort(addr.String())
	if err != nil {
		t.Fatalf("SplitHostPort(%q): %v", addr, err)
	}
	n, err := strconv.Atoi(p)
	if err != nil {
		t.Fatalf("Atoi(%q): %v", p, err)
	}
	return n
}

func TestSMTPStopIsIdempotent(t *testing.T) {
	s := &SMTP{Listeners: []*ListenerConfig{{Port: 0}}, log: zap.NewNop()}
	if err := s.Start(); err != nil {
		t.Fatalf("Start: %v", err)
	}
	if err := s.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}
	if err := s.Stop(); err != nil {
		t.Fatalf("second Stop: %v", err)
	}
}

func TestSMTPStartReleasesListenersOnFailure(t *testing.T) {
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("probe listen: %v", err)
	}
	free := portOf(t, probe.Addr())
	probe.Close()

	// Occupy the second port so the second bind in Start fails.
	blocked, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatalf("blocked listen: %v", err)
	}
	defer blocked.Close()
	taken := portOf(t, blocked.Addr())

	s := &SMTP{
		Listeners: []*ListenerConfig{{Port: free}, {Port: taken}},
		log:       zap.NewNop(),
	}
	err = s.Start()
	if err == nil {
		s.Stop()
		t.Fatal("expected Start to fail on an occupied port")
	}
	if !strings.Contains(err.Error(), "listen") {
		t.Errorf("unexpected error: %v", err)
	}

	// The first listener must have been released by the failed Start.
	ln, err := net.Listen("tcp", "127.0.0.1:"+strconv.Itoa(free))
	if err != nil {
		t.Fatalf("first listener leaked after failed Start: %v", err)
	}
	ln.Close()
}
