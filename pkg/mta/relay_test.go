package mta

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"github.com/frinknet/caddy-email/pkg/shared"
)

func TestRelaySpec(t *testing.T) {
	tests := []struct {
		relay    string
		smtpPort string
		wantHost string
		wantPort string
		wantOK   bool
	}{
		{"", "", "", "", false},
		{"relay.example.com", "", "relay.example.com", "25", true},
		{"relay.example.com", "2525", "relay.example.com", "2525", true},
		{"relay.example.com:587", "", "relay.example.com", "587", true},
		{"[::1]:2525", "", "::1", "2525", true},
	}
	for _, tc := range tests {
		m := &MTA{Relay: tc.relay, smtpPort: tc.smtpPort}
		host, port, ok := m.relaySpec()
		if host != tc.wantHost || port != tc.wantPort || ok != tc.wantOK {
			t.Errorf("relaySpec(%q, port %q) = (%q, %q, %v), want (%q, %q, %v)",
				tc.relay, tc.smtpPort, host, port, ok, tc.wantHost, tc.wantPort, tc.wantOK)
		}
	}
}

func TestRelayValidate(t *testing.T) {
	m := &MTA{Relay: "smarthost.example:2525"}
	m.applyDefaults()
	if err := m.Validate(); err != nil {
		t.Errorf("valid relay rejected: %v", err)
	}

	bad := &MTA{Relay: ":2525"}
	bad.applyDefaults()
	if err := bad.Validate(); err == nil {
		t.Error("relay with empty host should be rejected")
	}
}

func TestRelayGroupingSkipsMXLookup(t *testing.T) {
	dir := newSpool(t)
	m := &MTA{SpoolDir: dir, Hostname: "mail.test", Relay: "smarthost.example:2525", log: zap.NewNop()}
	m.mxCache = map[string]mxCacheEntry{}

	orig := lookupMX
	defer func() { lookupMX = orig }()
	lookupMX = func(string) ([]*net.MX, error) {
		t.Error("lookupMX must not be called when a relay is configured")
		return nil, nil
	}

	jobs := []*shared.Job{
		{ID: "a", From: "s@x.com", To: []string{"r1@one.example"}},
		{ID: "b", From: "s@x.com", To: []string{"r2@two.example"}},
	}
	groups := m.groupByMX(jobs)

	if len(groups) != 1 {
		t.Fatalf("expected 1 relay group, got %d", len(groups))
	}
	g, ok := groups[relayKey]
	if !ok {
		t.Fatalf("no group under %q: %v", relayKey, groups)
	}
	if len(g.hosts) != 1 || g.hosts[0] != "smarthost.example" {
		t.Errorf("relay hosts = %v, want [smarthost.example]", g.hosts)
	}
	if len(g.jobs) != 2 {
		t.Errorf("relay group has %d jobs, want 2", len(g.jobs))
	}
}

// TestRelayDelivery exercises the whole relay path: grouping picks the
// smarthost, and delivery dials the relay's port rather than the MX port
// (smtpPort is set to a dead port to prove the relay port wins).
func TestRelayDelivery(t *testing.T) {
	dir := newSpool(t)
	f := startFakeSMTP(t)
	m := &MTA{
		SpoolDir:       dir,
		Hostname:       "mail.test",
		log:            zap.NewNop(),
		Relay:          net.JoinHostPort("127.0.0.1", f.port()),
		smtpPort:       "1",
		ConnectTimeout: caddy.Duration(300 * time.Millisecond),
		CommandTimeout: caddy.Duration(5 * time.Second),
		DataTimeout:    caddy.Duration(5 * time.Second),
	}

	id := enqueueClaimed(t, dir, &shared.Envelope{
		From: "a@b.com",
		To:   []string{"c@d.com"},
	}, "relay body")
	j := &shared.Job{ID: id, From: "a@b.com", To: []string{"c@d.com"}}

	groups := m.groupByMX([]*shared.Job{j})
	g, ok := groups[relayKey]
	if !ok {
		t.Fatalf("no relay group produced: %v", groups)
	}
	m.deliverOne(g.hosts, j)

	if got := string(f.delivered()); !strings.Contains(got, "relay body") {
		t.Errorf("relayed body = %q, want it to contain %q", got, "relay body")
	}
	if _, err := os.Stat(filepath.Join(dir, shared.StateActive, "qf"+id)); err == nil {
		t.Error("job still in active/ after relay delivery")
	}
}
