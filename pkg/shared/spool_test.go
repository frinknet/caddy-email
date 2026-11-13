package shared

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var fixedTime = time.Date(2024, 1, 15, 12, 0, 0, 0, time.UTC)

func TestSignHMAC(t *testing.T) {
	t.Parallel()
	secret := "test-secret"
	body := []byte("hello world")
	sig := SignHMAC(secret, body)
	if sig == "" {
		t.Fatal("expected non-empty signature")
	}
	if !VerifyHMAC(secret, body, sig) {
		t.Fatal("expected valid signature")
	}
	if VerifyHMAC(secret, []byte("tampered"), sig) {
		t.Fatal("expected invalid signature for tampered body")
	}
	if VerifyHMAC("wrong-secret", body, sig) {
		t.Fatal("expected invalid signature for wrong secret")
	}
}

func TestBuildSimple(t *testing.T) {
	t.Parallel()
	raw := BuildSimple("alice@example.com", []string{"bob@example.com"}, "Hello", "World")
	s := string(raw)
	for want, msg := range map[string]string{
		"From: alice@example.com":           "missing From header",
		"To: bob@example.com":              "missing To header",
		"Subject: Hello":                   "missing Subject header",
		"World":                            "missing body",
	} {
		if !strings.Contains(s, want) {
			t.Error(msg)
		}
	}
}

func TestBuildSimpleMultipleRecipients(t *testing.T) {
	t.Parallel()
	raw := BuildSimple("alice@example.com", []string{"bob@example.com", "carol@example.com"}, "", "test")
	if !strings.Contains(string(raw), "To: bob@example.com, carol@example.com") {
		t.Error("expected both recipients in To header")
	}
}

func TestEncodeDecodeQF(t *testing.T) {
	t.Parallel()
	env := &Envelope{
		From: "alice@example.com",
		To:   []string{"bob@example.com"},
		Meta: map[string]string{"key": "val"},
	}
	job, err := parseQF(encodeQF(env, fixedTime))
	if err != nil {
		t.Fatalf("parseQF: %v", err)
	}
	if job.From != "alice@example.com" {
		t.Errorf("From = %q", job.From)
	}
	if len(job.To) != 1 || job.To[0] != "bob@example.com" {
		t.Errorf("To = %v", job.To)
	}
	if job.Attempts != 0 {
		t.Errorf("Attempts = %d", job.Attempts)
	}
}

func TestEncodeDecodeQFJob(t *testing.T) {
	t.Parallel()
	j := &Job{
		ID: "test123", Enqueued: fixedTime, Attempts: 3,
		NextAt: fixedTime.Add(3600), From: "alice@example.com",
		To: []string{"bob@example.com"},
	}
	parsed, err := parseQF(encodeQFJob(j, "temporary error"))
	if err != nil {
		t.Fatalf("parseQF: %v", err)
	}
	if parsed.From != "alice@example.com" {
		t.Errorf("From = %q", parsed.From)
	}
	if parsed.Attempts != 3 {
		t.Errorf("Attempts = %d", parsed.Attempts)
	}
	if parsed.NextAt.Unix() != fixedTime.Add(3600).Unix() {
		t.Errorf("NextAt = %v", parsed.NextAt)
	}
}

func TestNewID(t *testing.T) {
	t.Parallel()
	id1 := newID()
	id2 := newID()
	if id1 == "" || id2 == "" || id1 == id2 {
		t.Fatal("expected unique non-empty IDs")
	}
	if len(id1) < 10 {
		t.Fatalf("ID too short: %q", id1)
	}
}

func TestEnqueueScanClaimDeferBounceUnlink(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	env := &Envelope{From: "alice@example.com", To: []string{"bob@example.com"}}
	raw := []byte("From: alice\r\nTo: bob\r\n\r\nhello")

	id, err := Enqueue(dir, env, raw)
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if id == "" {
		t.Fatal("expected non-empty ID")
	}

	jobs, err := ScanEligible(dir, 0, 100)
	if err != nil {
		t.Fatalf("ScanEligible: %v", err)
	}
	if len(jobs) != 1 || jobs[0].From != "alice@example.com" {
		t.Fatalf("unexpected jobs: %+v", jobs)
	}

	if err := Claim(dir, id); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := Defer(dir, id, fixedTime.Add(60), 1, "try again"); err != nil {
		t.Fatalf("Defer: %v", err)
	}
	Bounce(dir, id)
	Unlink(dir, id) // no-op, should not panic
}

func TestRecoverActive(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	id, err := Enqueue(dir, &Envelope{From: "a@b", To: []string{"c@d"}}, []byte("test"))
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := Claim(dir, id); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if n := RecoverActive(dir, 0); n != 1 {
		t.Fatalf("expected 1 recovered, got %d", n)
	}
}

func TestMoveCorrupt(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	id, err := Enqueue(dir, &Envelope{From: "a@b", To: []string{"c@d"}}, []byte("test"))
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	moveCorrupt(dir, id)
	jobs, err := ScanEligible(dir, 0, 100)
	if err != nil {
		t.Fatalf("ScanEligible: %v", err)
	}
	if len(jobs) != 0 {
		t.Errorf("expected 0 jobs after moveCorrupt, got %d", len(jobs))
	}
}

func TestScanEligibleEmptyDir(t *testing.T) {
	t.Parallel()
	jobs, err := ScanEligible(t.TempDir(), 0, 100)
	if err != nil {
		t.Fatalf("ScanEligible on empty dir: %v", err)
	}
	if len(jobs) != 0 {
		t.Errorf("expected 0 jobs, got %d", len(jobs))
	}
}

func TestEnqueueCorruptQF(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	id, err := Enqueue(dir, &Envelope{From: "a@b", To: []string{"c@d"}}, []byte("body"))
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	// Write a qf with wrong schema version to trigger moveCorrupt
	if err := os.WriteFile(filepath.Join(dir, "incoming", "qf"+id), []byte("V0\n"), 0600); err != nil {
		t.Fatalf("write corrupt qf: %v", err)
	}
	jobs, err := ScanEligible(dir, 0, 100)
	if err != nil {
		t.Fatalf("ScanEligible: %v", err)
	}
	if len(jobs) != 0 {
		t.Errorf("expected 0 jobs for corrupt qf, got %d", len(jobs))
	}
}
