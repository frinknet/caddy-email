package mta

import (
	"crypto/rand"
	"crypto/rsa"
	"strings"
	"testing"
)

func benchDKIMConfig(b *testing.B) *DKIMConfig {
	b.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		b.Fatalf("generate rsa key: %v", err)
	}
	return &DKIMConfig{Selector: "sel", Domain: "example.com", parsedKey: key}
}

func benchDKIMBody() []byte {
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

// BenchmarkDKIMSign measures the per-message signing cost on the delivery
// critical path: a SHA-256 body hash plus an RSA-2048 PKCS#1 v1.5 signature.
func BenchmarkDKIMSign(b *testing.B) {
	cfg := benchDKIMConfig(b)
	body := benchDKIMBody()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := dkimSign(body, cfg, "example.com"); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkDKIMSignParallel measures aggregate signing throughput across all
// cores, matching how the MTA signs concurrent deliveries in the worker pool.
func BenchmarkDKIMSignParallel(b *testing.B) {
	cfg := benchDKIMConfig(b)
	body := benchDKIMBody()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := dkimSign(body, cfg, "example.com"); err != nil {
				b.Fatal(err)
			}
		}
	})
}
