package mta

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/frinknet/caddy-email/pkg/shared"
)

func TestParseDKIMKey(t *testing.T) {
	key := `-----BEGIN PRIVATE KEY-----
MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7VJTUt9Us8cKj
MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6VVMi3v3k2o9Wk4ADgF/3mD6gTyQpDp
CgN9W9aUJ4Xz9G6Vx7gJmYdQq6F7yKjLx8Dq7vF6JnL8X0f6xKPgHx7uL7dK
8Z5fJ8V7Y7f6gK8Z7f6gK8Z7f6gK8Z7f6gK8Z7f6gK8Z7f6gK8Z7f6gK8Z7f6
-----END PRIVATE KEY-----`
	_, err := parseDKIMKey(key)
	if err == nil {
		t.Error("expected error for invalid PEM, got nil")
	}
}

func TestDKIMSignNoKey(t *testing.T) {
	body := []byte("From: test@example.com\r\nSubject: test\r\n\r\nhello")
	signed, err := dkimSign(body, nil, "example.com")
	if err != nil {
		t.Fatalf("dkimSign with nil config: %v", err)
	}
	if string(signed) != string(body) {
		t.Error("expected no change when DKIM config is nil")
	}
}

func TestBuildDSN(t *testing.T) {
	m := &MTA{Hostname: "mail.test"}
	j := &shared.Job{
		ID:   "test123",
		From: "sender@example.com",
		To:   []string{"rcpt@example.com"},
	}
	dsn := m.buildDSN(j, "user unknown")
	s := string(dsn)
	if !strings.Contains(s, "MAILER-DAEMON@mail.test") {
		t.Error("missing From header")
	}
	if !strings.Contains(s, "sender@example.com") {
		t.Error("missing To header")
	}
	if !strings.Contains(s, "user unknown") {
		t.Error("missing diagnostic message")
	}
	if !strings.Contains(s, "multipart/report") {
		t.Error("missing multipart/report content type")
	}
	if !strings.Contains(s, "message/delivery-status") {
		t.Error("missing delivery-status part")
	}
}

func TestReEnqueue(t *testing.T) {
	dir := t.TempDir()
	m := &MTA{
		SpoolDir: dir,
	}
	for _, sub := range []string{shared.StateIncoming, shared.StateActive, shared.StateDeferred} {
		os.MkdirAll(dir+"/"+sub, 0700)
	}

	j := &shared.Job{
		ID:   "orig123",
		From: "alice@example.com",
		To:   []string{"bob@example.com"},
	}
	body := []byte("test body")
	m.reEnqueue(j, body, []string{"bob@example.com"})

	// Should have created a new job in deferred/
	defDir := filepath.Join(dir, shared.StateDeferred)
	entries, err := os.ReadDir(defDir)
	if err != nil {
		t.Fatalf("read deferred dir: %v", err)
	}
	var qfCount int
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), "qf") {
			qfCount++
		}
	}
	if qfCount != 1 {
		t.Fatalf("expected 1 qf file in deferred, got %d", qfCount)
	}
}
