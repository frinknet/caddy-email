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
		"From: alice@example.com": "missing From header",
		"To: bob@example.com":     "missing To header",
		"Subject: Hello":          "missing Subject header",
		"World":                   "missing body",
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
	if job.Meta["key"] != "val" {
		t.Errorf("Meta = %v", job.Meta)
	}
}

func TestEncodeDecodeQFJob(t *testing.T) {
	t.Parallel()
	j := &Job{
		ID: "test123", Enqueued: fixedTime, Attempts: 3,
		NextAt: fixedTime.Add(3600), From: "alice@example.com",
		To: []string{"bob@example.com"}, Meta: map[string]string{"trace": "xyz"},
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
	if parsed.Meta["trace"] != "xyz" {
		t.Errorf("Meta = %v", parsed.Meta)
	}
}

func TestDeferPreservesMeta(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	env := &Envelope{From: "a@b", To: []string{"c@d"}, Meta: map[string]string{"trace": "xyz"}}
	id, err := Enqueue(dir, env, []byte("body"))
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := Claim(dir, id); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := Defer(dir, id, time.Now().Add(time.Minute), 1, "later"); err != nil {
		t.Fatalf("Defer: %v", err)
	}
	data, err := os.ReadFile(filepath.Join(dir, StateDeferred, "qf"+id))
	if err != nil {
		t.Fatalf("read deferred qf: %v", err)
	}
	j, err := parseQF(data)
	if err != nil {
		t.Fatalf("parseQF: %v", err)
	}
	if j.Meta["trace"] != "xyz" {
		t.Errorf("Meta lost across Defer: %v", j.Meta)
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

func TestSweepDeferred(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	enqueueClaimed := func() string {
		id, err := Enqueue(dir, &Envelope{From: "a@b", To: []string{"c@d"}}, []byte("body"))
		if err != nil {
			t.Fatalf("Enqueue: %v", err)
		}
		if err := Claim(dir, id); err != nil {
			t.Fatalf("Claim: %v", err)
		}
		return id
	}

	ready := enqueueClaimed()
	if err := Defer(dir, ready, time.Now().Add(-time.Minute), 1, "retry"); err != nil {
		t.Fatalf("Defer ready: %v", err)
	}
	waiting := enqueueClaimed()
	if err := Defer(dir, waiting, time.Now().Add(time.Hour), 1, "later"); err != nil {
		t.Fatalf("Defer waiting: %v", err)
	}

	if n := SweepDeferred(dir, time.Now()); n != 1 {
		t.Fatalf("expected 1 swept, got %d", n)
	}
	jobs, err := ScanEligible(dir, 0, 100)
	if err != nil {
		t.Fatalf("ScanEligible: %v", err)
	}
	if len(jobs) != 1 || jobs[0].ID != ready {
		t.Fatalf("expected only the ready job back in incoming, got %+v", jobs)
	}
	if _, err := os.Stat(filepath.Join(dir, StateIncoming, "df"+ready)); err != nil {
		t.Fatalf("df not moved back: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, StateDeferred, "qf"+waiting)); err != nil {
		t.Fatalf("waiting job should stay deferred: %v", err)
	}
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
	if n := RecoverActive(dir, 0, nil); n != 1 {
		t.Fatalf("expected 1 recovered, got %d", n)
	}
}

// TestRecoverActiveTooRecent checks that a job claimed within the cutoff is not
// yanked from under a live delivery, and that it is recovered once it ages out.
func TestRecoverActiveTooRecent(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	id, err := Enqueue(dir, &Envelope{From: "a@b", To: []string{"c@d"}}, []byte("test"))
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := Claim(dir, id); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	// Its qf was just written, so a one-hour cutoff excludes it.
	if n := RecoverActive(dir, time.Hour, nil); n != 0 {
		t.Fatalf("recent job should not be recovered, got %d", n)
	}
	if _, err := os.Stat(filepath.Join(dir, StateActive, "qf"+id)); err != nil {
		t.Fatalf("recent job should stay active: %v", err)
	}
	// A nil cutoff recovers it.
	if n := RecoverActive(dir, 0, nil); n != 1 {
		t.Fatalf("expected 1 recovered with no cutoff, got %d", n)
	}
}

// TestRecoverActiveSkipsInFlight checks that the skip predicate protects a job
// the process is currently delivering.
func TestRecoverActiveSkipsInFlight(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	id, err := Enqueue(dir, &Envelope{From: "a@b", To: []string{"c@d"}}, []byte("test"))
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := Claim(dir, id); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if n := RecoverActive(dir, 0, func(got string) bool { return got == id }); n != 0 {
		t.Fatalf("in-flight job should be skipped, got %d", n)
	}
}

// TestReconcileSpoolHealsSplitPair checks that a qf and df split across state
// directories are reunited according to where the df landed.
func TestReconcileSpoolHealsSplitPair(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	id, err := Enqueue(dir, &Envelope{From: "a@b", To: []string{"c@d"}}, []byte("body"))
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := Claim(dir, id); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	// Simulate a crash mid-Defer: df reached deferred/, qf stayed in active/.
	def := filepath.Join(dir, StateDeferred)
	if err := os.MkdirAll(def, 0700); err != nil {
		t.Fatalf("mkdir deferred: %v", err)
	}
	if err := os.Rename(filepath.Join(dir, StateActive, "df"+id), filepath.Join(def, "df"+id)); err != nil {
		t.Fatalf("split df: %v", err)
	}

	if n := ReconcileSpool(dir); n != 1 {
		t.Fatalf("expected 1 repair, got %d", n)
	}
	if _, err := os.Stat(filepath.Join(def, "qf"+id)); err != nil {
		t.Errorf("qf was not reunited with df in deferred/: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, StateActive, "qf"+id)); !os.IsNotExist(err) {
		t.Errorf("qf still in active/: %v", err)
	}
}

// TestReconcileSpoolRemovesOrphanBody checks that a df with no qf (an
// interrupted Enqueue) is removed rather than growing the spool forever.
func TestReconcileSpoolRemovesOrphanBody(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	inc := filepath.Join(dir, StateIncoming)
	if err := os.MkdirAll(inc, 0700); err != nil {
		t.Fatalf("mkdir incoming: %v", err)
	}
	orphan := filepath.Join(inc, "dforphan")
	if err := os.WriteFile(orphan, []byte("body"), 0600); err != nil {
		t.Fatalf("write orphan: %v", err)
	}
	if n := ReconcileSpool(dir); n != 1 {
		t.Fatalf("expected 1 repair, got %d", n)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Errorf("orphan df was not removed: %v", err)
	}
}

// TestReconcileSpoolQuarantinesBodylessQF checks that a committed qf with no df
// is moved to corrupt/ instead of sitting in the queue undeliverable.
func TestReconcileSpoolQuarantinesBodylessQF(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	id, err := Enqueue(dir, &Envelope{From: "a@b", To: []string{"c@d"}}, []byte("body"))
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := os.Remove(filepath.Join(dir, StateIncoming, "df"+id)); err != nil {
		t.Fatalf("remove df: %v", err)
	}
	if n := ReconcileSpool(dir); n != 1 {
		t.Fatalf("expected 1 repair, got %d", n)
	}
	if _, err := os.Stat(filepath.Join(dir, StateCorrupt, "qf"+id)); err != nil {
		t.Errorf("bodyless qf was not quarantined: %v", err)
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

func TestSanitizeHeaderValue(t *testing.T) {
	t.Parallel()
	cases := map[string]string{
		"plain":            "plain",
		"a\r\nBcc: x@y":    "a  Bcc: x@y",
		"line1\nline2":     "line1 line2",
		"carriage\rreturn": "carriage return",
	}
	for in, want := range cases {
		if got := SanitizeHeaderValue(in); got != want {
			t.Errorf("SanitizeHeaderValue(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestValidAddress(t *testing.T) {
	t.Parallel()
	valid := []string{"a@b.com", "user.name+tag@example.co.uk", "Name <user@example.com>"}
	for _, a := range valid {
		if !ValidAddress(a) {
			t.Errorf("ValidAddress(%q) = false, want true", a)
		}
	}
	invalid := []string{"", "no-at-sign", "a@b\r\nBcc: evil@x.com", "a@b\nx", "<>"}
	for _, a := range invalid {
		if ValidAddress(a) {
			t.Errorf("ValidAddress(%q) = true, want false", a)
		}
	}
}

func TestBuildMessageSanitizesHeaders(t *testing.T) {
	t.Parallel()
	raw := BuildMessage("a@b.com", []string{"c@d.com"}, nil, "", "Hi\r\nBcc: evil@x.com", "body")
	s := string(raw)
	if strings.Contains(s, "\r\nBcc: evil@x.com") {
		t.Errorf("subject injected a header:\n%q", s)
	}
}

func TestSpoolSizeAndPruneBounce(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	env := &Envelope{From: "a@b", To: []string{"c@d"}}
	id, err := Enqueue(dir, env, []byte("0123456789"))
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	size, err := SpoolSize(dir)
	if err != nil {
		t.Fatalf("SpoolSize: %v", err)
	}
	if size < 10 {
		t.Fatalf("SpoolSize = %d, want >= 10", size)
	}

	if err := Claim(dir, id); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	Bounce(dir, id)
	// Backdate the archived files so they are eligible for pruning.
	past := time.Now().Add(-48 * time.Hour)
	for _, name := range []string{"qf" + id, "df" + id} {
		p := filepath.Join(dir, StateBounce, name)
		if err := os.Chtimes(p, past, past); err != nil {
			t.Fatalf("chtimes %s: %v", p, err)
		}
	}
	if n := PruneBounce(dir, time.Now().Add(-24*time.Hour)); n != 2 {
		t.Fatalf("PruneBounce removed %d files, want 2", n)
	}
	entries, err := os.ReadDir(filepath.Join(dir, StateBounce))
	if err != nil {
		t.Fatalf("read bounce: %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("expected empty bounce dir, got %d entries", len(entries))
	}
}

func TestParseQFRejectsMalformedCounters(t *testing.T) {
	t.Parallel()
	for _, bad := range []string{"Nabc", "Pxyz"} {
		data := []byte("V8\nT1700000000\n" + bad + "\nS a@b.com\nR c@d.com\n")
		if _, err := parseQF(data); err == nil {
			t.Errorf("parseQF accepted malformed counter %q", bad)
		}
	}
}

func TestPruneCorrupt(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	cor := filepath.Join(dir, StateCorrupt)
	if err := os.MkdirAll(cor, 0700); err != nil {
		t.Fatalf("mkdir corrupt: %v", err)
	}
	p := filepath.Join(cor, "qfold")
	if err := os.WriteFile(p, []byte("x"), 0600); err != nil {
		t.Fatalf("write corrupt file: %v", err)
	}
	past := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(p, past, past); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	if n := PruneCorrupt(dir, time.Now().Add(-24*time.Hour)); n != 1 {
		t.Fatalf("PruneCorrupt removed %d files, want 1", n)
	}
	if _, err := os.Stat(p); !os.IsNotExist(err) {
		t.Errorf("corrupt file still present: %v", err)
	}
}
