package shared

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func benchSpool(b *testing.B) string {
	b.Helper()
	dir := b.TempDir()
	for _, sub := range []string{
		StateIncoming, StateActive, StateDeferred,
		StateBounce, StateCorrupt, StateHold,
	} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0700); err != nil {
			b.Fatalf("mkdir %s: %v", sub, err)
		}
	}
	return dir
}

func benchBody() []byte {
	return []byte("From: alice@example.com\r\n" +
		"To: bob@example.com\r\n" +
		"Subject: hello\r\n" +
		"Date: Thu, 01 Jan 2026 00:00:00 +0000\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" +
		strings.Repeat("The quick brown fox jumps over the lazy dog. ", 20) +
		"\r\n")
}

func benchEnvelope() *Envelope {
	return &Envelope{From: "alice@example.com", To: []string{"bob@example.com"}}
}

// BenchmarkEnqueue measures single-message spool ingest: two fsync'd writes
// (df then qf) plus the directory sync. This is the ceiling for how fast
// sendmail can accept a message.
func BenchmarkEnqueue(b *testing.B) {
	dir := benchSpool(b)
	env := benchEnvelope()
	raw := benchBody()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := Enqueue(dir, env, raw); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkScanEligible measures a read-only queue scan over 1000 waiting jobs.
func BenchmarkScanEligible(b *testing.B) {
	dir := benchSpool(b)
	env := benchEnvelope()
	raw := benchBody()
	for i := 0; i < 1000; i++ {
		if _, err := Enqueue(dir, env, raw); err != nil {
			b.Fatal(err)
		}
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		jobs, err := ScanEligible(dir, 0, 0)
		if err != nil {
			b.Fatal(err)
		}
		if len(jobs) != 1000 {
			b.Fatalf("got %d jobs, want 1000", len(jobs))
		}
	}
}

// BenchmarkDispatchCycle measures the per-tick dispatch path: scan, claim
// (rename into active/), and unlink after delivery for a 100-job batch.
func BenchmarkDispatchCycle(b *testing.B) {
	dir := benchSpool(b)
	env := benchEnvelope()
	raw := benchBody()
	const batch = 100
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		b.StopTimer()
		for j := 0; j < batch; j++ {
			if _, err := Enqueue(dir, env, raw); err != nil {
				b.Fatal(err)
			}
		}
		b.StartTimer()
		jobs, err := ScanEligible(dir, 0, 0)
		if err != nil {
			b.Fatal(err)
		}
		for _, j := range jobs {
			if err := Claim(dir, j.ID); err != nil {
				b.Fatal(err)
			}
			Unlink(dir, j.ID)
		}
	}
}

func BenchmarkBuildMessage(b *testing.B) {
	to := []string{"bob@example.com", "carol@example.com"}
	body := strings.Repeat("The quick brown fox jumps over the lazy dog. ", 20)
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = BuildMessage("alice@example.com", to, nil, "", "hello", body)
	}
}

func BenchmarkEncodeParseQF(b *testing.B) {
	env := &Envelope{
		From: "alice@example.com",
		To:   []string{"bob@example.com", "carol@example.com"},
		Meta: map[string]string{"webhook": "https://example.com/hook", "trace": "abc123"},
	}
	data := encodeQF(env, time.Now())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		j, err := parseQF(data)
		if err != nil {
			b.Fatal(err)
		}
		_ = encodeQFJob(j, "")
	}
}
