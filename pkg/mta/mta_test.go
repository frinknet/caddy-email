package mta

import (
	"bufio"
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"github.com/frinknet/caddy-email/pkg/shared"
)

// newSpool creates a spool directory with every state subdirectory.
func newSpool(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, sub := range []string{
		shared.StateIncoming, shared.StateActive, shared.StateDeferred,
		shared.StateBounce, shared.StateCorrupt,
	} {
		if err := os.MkdirAll(filepath.Join(dir, sub), 0700); err != nil {
			t.Fatalf("mkdir %s: %v", sub, err)
		}
	}
	return dir
}

// enqueueClaimed enqueues a job and moves it into active/, returning its ID.
func enqueueClaimed(t *testing.T, dir string, env *shared.Envelope, body string) string {
	t.Helper()
	id, err := shared.Enqueue(dir, env, []byte(body))
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	if err := shared.Claim(dir, id); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	return id
}

func countPrefix(t *testing.T, dir string, prefix string) int {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	n := 0
	for _, e := range entries {
		if strings.HasPrefix(e.Name(), prefix) {
			n++
		}
	}
	return n
}

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
		SpoolDir:   dir,
		MaxRetries: 5,
		log:        zap.NewNop(),
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

	// The re-enqueued df must hold the raw body passed in, not a signed copy.
	// Enqueue stamps a generated Message-ID, so only the body must survive.
	for _, e := range entries {
		if !strings.HasPrefix(e.Name(), "df") {
			continue
		}
		got, err := os.ReadFile(filepath.Join(defDir, e.Name()))
		if err != nil {
			t.Fatalf("read %s: %v", e.Name(), err)
		}
		if !strings.HasSuffix(string(got), string(body)) {
			t.Errorf("deferred df = %q, want it to end with %q", got, body)
		}
		if strings.Contains(string(got), "DKIM-Signature") {
			t.Errorf("deferred df carries a signature: %q", got)
		}
	}
}

func TestMTAValidateNumeric(t *testing.T) {
	if err := (&MTA{Concurrency: -1}).Validate(); err == nil {
		t.Error("expected error for negative concurrency")
	}
	if err := (&MTA{PerMXConcurrency: -1}).Validate(); err == nil {
		t.Error("expected error for negative per_mx_concurrency")
	}
	if err := (&MTA{MaxBatch: -1}).Validate(); err == nil {
		t.Error("expected error for negative max_batch")
	}
	if err := (&MTA{MaxRetries: -1}).Validate(); err == nil {
		t.Error("expected error for negative max_retries")
	}
	for name, m := range map[string]*MTA{
		"tick_interval":    {TickInterval: caddy.Duration(-time.Second)},
		"connect_timeout":  {ConnectTimeout: caddy.Duration(-time.Second)},
		"data_timeout":     {DataTimeout: caddy.Duration(-time.Second)},
		"command_timeout":  {CommandTimeout: caddy.Duration(-time.Second)},
		"bounce_retention": {BounceRetention: caddy.Duration(-time.Second)},
		"initial_backoff":  {InitialBackoff: caddy.Duration(-time.Second)},
		"max_backoff":      {MaxBackoff: caddy.Duration(-time.Second)},
	} {
		if err := m.Validate(); err == nil {
			t.Errorf("expected error for negative %s", name)
		}
	}
	if err := (&MTA{
		InitialBackoff: caddy.Duration(time.Hour),
		MaxBackoff:     caddy.Duration(time.Minute),
	}).Validate(); err == nil {
		t.Error("expected error when initial_backoff exceeds max_backoff")
	}

	m := &MTA{}
	m.applyDefaults()
	if err := m.Validate(); err != nil {
		t.Errorf("defaulted config should validate, got %v", err)
	}
}

func TestSplitMultiDomain(t *testing.T) {
	dir := t.TempDir()
	for _, sub := range []string{shared.StateIncoming, shared.StateActive} {
		os.MkdirAll(filepath.Join(dir, sub), 0700)
	}
	m := &MTA{SpoolDir: dir, log: zap.NewNop()}

	id, err := shared.Enqueue(dir, &shared.Envelope{
		From: "alice@example.com",
		To:   []string{"one@a.com", "two@a.com", "three@b.com"},
	}, []byte("body"))
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}

	jobs, err := shared.ScanEligible(dir, 0, 100)
	if err != nil {
		t.Fatalf("ScanEligible: %v", err)
	}
	out := m.splitMultiDomain(jobs)
	if len(out) != 2 {
		t.Fatalf("expected 2 single-domain jobs, got %d: %+v", len(out), out)
	}

	counts := map[string]int{}
	var origKept bool
	for _, j := range out {
		dom := recipientDomain(j.To[0])
		for _, r := range j.To {
			if recipientDomain(r) != dom {
				t.Fatalf("job %s spans multiple domains: %v", j.ID, j.To)
			}
		}
		counts[dom] += len(j.To)
		if j.ID == id {
			origKept = true
			if dom != "a.com" {
				t.Errorf("original job kept wrong domain: %v", j.To)
			}
		}
	}
	if counts["a.com"] != 2 || counts["b.com"] != 1 {
		t.Fatalf("unexpected split: %v", counts)
	}
	if !origKept {
		t.Error("original job ID was not preserved")
	}

	// The rewritten qf on disk must carry only the first domain's recipients.
	data, err := os.ReadFile(filepath.Join(dir, shared.StateIncoming, "qf"+id))
	if err != nil {
		t.Fatalf("read rewritten qf: %v", err)
	}
	var rcpts []string
	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "R") {
			rcpts = append(rcpts, line[1:])
		}
	}
	if len(rcpts) != 2 {
		t.Fatalf("expected 2 recipients in rewritten qf, got %v", rcpts)
	}
}

func TestFailPermanentQueuesDSN(t *testing.T) {
	dir := newSpool(t)
	m := &MTA{SpoolDir: dir, Hostname: "mail.test", MaxRetries: 5, log: zap.NewNop()}

	id := enqueueClaimed(t, dir, &shared.Envelope{
		From: "sender@example.com",
		To:   []string{"rcpt@example.com"},
	}, "body")
	j := &shared.Job{ID: id, From: "sender@example.com", To: []string{"rcpt@example.com"}}

	m.failPermanent(j, "user unknown")

	// The original message is archived in bounce/.
	if _, err := os.Stat(filepath.Join(dir, shared.StateBounce, "qf"+id)); err != nil {
		t.Fatalf("original not archived in bounce/: %v", err)
	}

	// A DSN is queued for delivery back to the sender.
	jobs, err := shared.ScanEligible(dir, 0, 100)
	if err != nil {
		t.Fatalf("ScanEligible: %v", err)
	}
	var dsn *shared.Job
	for _, d := range jobs {
		if d.From == "MAILER-DAEMON@mail.test" {
			dsn = d
		}
	}
	if dsn == nil {
		t.Fatal("no DSN queued for the sender")
	}
	if len(dsn.To) != 1 || dsn.To[0] != "sender@example.com" {
		t.Errorf("DSN recipients = %v, want [sender@example.com]", dsn.To)
	}
	if dsn.Meta[metaDSN] != "1" {
		t.Errorf("DSN job not marked to prevent loops: %v", dsn.Meta)
	}
}

func TestBounceLoopSuppressed(t *testing.T) {
	dir := newSpool(t)
	m := &MTA{SpoolDir: dir, Hostname: "mail.test", log: zap.NewNop()}

	// A null sender must never receive a bounce.
	id1 := enqueueClaimed(t, dir, &shared.Envelope{
		From: "",
		To:   []string{"rcpt@example.com"},
	}, "body")
	m.failPermanent(&shared.Job{ID: id1, From: "", To: []string{"rcpt@example.com"}}, "nope")

	// A DSN must never generate another DSN.
	id2 := enqueueClaimed(t, dir, &shared.Envelope{
		From: "sender@example.com",
		To:   []string{"rcpt@example.com"},
		Meta: map[string]string{metaDSN: "1"},
	}, "body")
	m.failPermanent(&shared.Job{
		ID: id2, From: "sender@example.com", To: []string{"rcpt@example.com"},
		Meta: map[string]string{metaDSN: "1"},
	}, "nope")

	if n := countPrefix(t, filepath.Join(dir, shared.StateIncoming), "qf"); n != 0 {
		t.Errorf("expected no DSN queued, found %d jobs in incoming/", n)
	}
	if n := countPrefix(t, filepath.Join(dir, shared.StateBounce), "qf"); n != 2 {
		t.Errorf("expected 2 archived messages, found %d", n)
	}
}

func TestReEnqueueExhaustedBounces(t *testing.T) {
	dir := newSpool(t)
	m := &MTA{SpoolDir: dir, Hostname: "mail.test", MaxRetries: 0, log: zap.NewNop()}

	id := enqueueClaimed(t, dir, &shared.Envelope{
		From: "sender@example.com",
		To:   []string{"rcpt@example.com"},
	}, "body")
	j := &shared.Job{ID: id, From: "sender@example.com", To: []string{"rcpt@example.com"}, Attempts: 0}

	m.reEnqueue(j, []byte("body"), []string{"rcpt@example.com"})

	// Nothing should be left in deferred/; a DSN should be queued instead.
	if n := countPrefix(t, filepath.Join(dir, shared.StateDeferred), "qf"); n != 0 {
		t.Errorf("expected no deferred job, found %d", n)
	}
	if n := countPrefix(t, filepath.Join(dir, shared.StateIncoming), "qf"); n != 1 {
		t.Errorf("expected 1 queued DSN, found %d", n)
	}
}

func TestClassifyMX(t *testing.T) {
	hosts, null := classifyMX([]*net.MX{{Host: ".", Pref: 0}})
	if !null || len(hosts) != 0 {
		t.Errorf("null MX: hosts=%v null=%v, want empty hosts and null=true", hosts, null)
	}

	hosts, null = classifyMX([]*net.MX{
		{Host: "mx2.example.com.", Pref: 20},
		{Host: "mx1.example.com.", Pref: 10},
	})
	if null {
		t.Error("normal MX set classified as null")
	}
	if len(hosts) != 2 || hosts[0] != "mx1.example.com" || hosts[1] != "mx2.example.com" {
		t.Errorf("hosts = %v, want preference order with trailing dots trimmed", hosts)
	}
}

func TestResolveTargetNullMX(t *testing.T) {
	orig := lookupMX
	defer func() { lookupMX = orig }()
	lookupMX = func(string) ([]*net.MX, error) {
		return []*net.MX{{Host: ".", Pref: 0}}, nil
	}

	m := &MTA{MxCacheTTL: caddy.Duration(time.Minute), log: zap.NewNop()}
	m.mxCache = map[string]mxCacheEntry{}
	target, err := m.resolveTarget("example.com")
	if err != nil {
		t.Fatalf("resolveTarget: %v", err)
	}
	if !target.null {
		t.Error("expected null MX target")
	}
}

func TestResolveTargetImplicitMXOnNotFound(t *testing.T) {
	orig := lookupMX
	defer func() { lookupMX = orig }()
	lookupMX = func(string) ([]*net.MX, error) {
		return nil, &net.DNSError{Err: "no such host", Name: "example.com", IsNotFound: true}
	}

	m := &MTA{MxCacheTTL: caddy.Duration(time.Minute), log: zap.NewNop()}
	m.mxCache = map[string]mxCacheEntry{}
	target, err := m.resolveTarget("example.com")
	if err != nil {
		t.Fatalf("resolveTarget: %v", err)
	}
	if target.null || len(target.hosts) != 1 || target.hosts[0] != "example.com" {
		t.Errorf("expected implicit MX to the domain itself, got %+v", target)
	}
}

func TestResolveTargetTemporaryError(t *testing.T) {
	orig := lookupMX
	defer func() { lookupMX = orig }()
	lookupMX = func(string) ([]*net.MX, error) {
		return nil, &net.DNSError{Err: "timeout", Name: "example.com", IsTimeout: true}
	}

	m := &MTA{MxCacheTTL: caddy.Duration(time.Minute), log: zap.NewNop()}
	m.mxCache = map[string]mxCacheEntry{}
	if _, err := m.resolveTarget("example.com"); err == nil {
		t.Fatal("expected temporary DNS error to surface so the job is deferred")
	}
}

func TestGroupByMXNullBounces(t *testing.T) {
	dir := newSpool(t)
	m := &MTA{SpoolDir: dir, Hostname: "mail.test", MxCacheTTL: caddy.Duration(time.Minute), log: zap.NewNop()}
	m.mxCache = map[string]mxCacheEntry{}

	orig := lookupMX
	defer func() { lookupMX = orig }()
	lookupMX = func(string) ([]*net.MX, error) {
		return []*net.MX{{Host: ".", Pref: 0}}, nil
	}

	id := enqueueClaimed(t, dir, &shared.Envelope{
		From: "sender@example.com",
		To:   []string{"rcpt@no-mail.example"},
	}, "body")
	j := &shared.Job{ID: id, From: "sender@example.com", To: []string{"rcpt@no-mail.example"}}

	m.groupByMX([]*shared.Job{j})

	if _, err := os.Stat(filepath.Join(dir, shared.StateBounce, "qf"+id)); err != nil {
		t.Fatalf("null-MX job was not bounced: %v", err)
	}
	if n := countPrefix(t, filepath.Join(dir, shared.StateIncoming), "qf"); n != 1 {
		t.Errorf("expected 1 queued DSN, found %d", n)
	}
}

// fakeSMTP is a minimal SMTP server that accepts a single message.
type fakeSMTP struct {
	ln    net.Listener
	mu    sync.Mutex
	data  []byte
	rcpts []string
}

func startFakeSMTP(t *testing.T) *fakeSMTP {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	f := &fakeSMTP{ln: ln}
	go f.serve()
	t.Cleanup(func() { ln.Close() })
	return f
}

func (f *fakeSMTP) port() string {
	_, port, err := net.SplitHostPort(f.ln.Addr().String())
	if err != nil {
		return ""
	}
	return port
}

func (f *fakeSMTP) serve() {
	for {
		conn, err := f.ln.Accept()
		if err != nil {
			return
		}
		go f.handle(conn)
	}
}

func (f *fakeSMTP) handle(conn net.Conn) {
	defer conn.Close()
	br := bufio.NewReader(conn)
	bw := bufio.NewWriter(conn)
	write := func(s string) {
		bw.WriteString(s + "\r\n")
		bw.Flush()
	}
	write("220 fake ESMTP")
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		cmd := strings.ToUpper(strings.TrimRight(line, "\r\n"))
		switch {
		case strings.HasPrefix(cmd, "EHLO"):
			bw.WriteString("250-fake\r\n250 OK\r\n")
			bw.Flush()
		case strings.HasPrefix(cmd, "HELO"):
			write("250 fake")
		case strings.HasPrefix(cmd, "MAIL"), strings.HasPrefix(cmd, "RSET"), strings.HasPrefix(cmd, "NOOP"):
			write("250 OK")
		case strings.HasPrefix(cmd, "RCPT"):
			f.mu.Lock()
			f.rcpts = append(f.rcpts, line)
			f.mu.Unlock()
			write("250 OK")
		case strings.HasPrefix(cmd, "DATA"):
			write("354 go")
			var body []byte
			for {
				dl, err := br.ReadString('\n')
				if err != nil {
					return
				}
				if dl == ".\r\n" || dl == ".\n" {
					break
				}
				body = append(body, dl...)
			}
			f.mu.Lock()
			f.data = body
			f.mu.Unlock()
			write("250 accepted")
		case strings.HasPrefix(cmd, "QUIT"):
			write("221 bye")
			return
		default:
			write("250 OK")
		}
	}
}

func (f *fakeSMTP) delivered() []byte {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.data
}

func TestDeliverOneFailover(t *testing.T) {
	dir := newSpool(t)
	f := startFakeSMTP(t)
	m := &MTA{
		SpoolDir:       dir,
		Hostname:       "mail.test",
		log:            zap.NewNop(),
		ConnectTimeout: caddy.Duration(300 * time.Millisecond),
		CommandTimeout: caddy.Duration(5 * time.Second),
		DataTimeout:    caddy.Duration(5 * time.Second),
		smtpPort:       f.port(),
	}

	id := enqueueClaimed(t, dir, &shared.Envelope{
		From: "a@b.com",
		To:   []string{"c@d.com"},
	}, "From: a@b.com\r\nTo: c@d.com\r\n\r\nhello world")
	j := &shared.Job{ID: id, From: "a@b.com", To: []string{"c@d.com"}}

	// 192.0.2.1 is TEST-NET-1 and never answers; delivery must fail over to
	// the working host rather than give up on the first MX.
	m.deliverOne([]string{"192.0.2.1", "127.0.0.1"}, j)

	if _, err := os.Stat(filepath.Join(dir, shared.StateActive, "qf"+id)); !os.IsNotExist(err) {
		t.Fatalf("job not unlinked after failover delivery: %v", err)
	}
	if body := f.delivered(); !strings.Contains(string(body), "hello world") {
		t.Errorf("body not delivered over failover: %q", body)
	}
	got := string(f.delivered())
	for _, want := range []string{"Received: from mail.test", "by 127.0.0.1", "id " + id} {
		if !strings.Contains(got, want) {
			t.Errorf("delivered message missing %q:\n%s", want, got)
		}
	}
}

func TestDeliverOneRequireTLSDefers(t *testing.T) {
	dir := newSpool(t)
	f := startFakeSMTP(t)
	m := &MTA{
		SpoolDir:       dir,
		Hostname:       "mail.test",
		log:            zap.NewNop(),
		RequireTLS:     true,
		ConnectTimeout: caddy.Duration(2 * time.Second),
		CommandTimeout: caddy.Duration(5 * time.Second),
		DataTimeout:    caddy.Duration(5 * time.Second),
		MaxRetries:     5,
		smtpPort:       f.port(),
	}

	id := enqueueClaimed(t, dir, &shared.Envelope{
		From: "a@b.com",
		To:   []string{"c@d.com"},
	}, "body")
	j := &shared.Job{ID: id, From: "a@b.com", To: []string{"c@d.com"}}

	m.deliverOne([]string{"127.0.0.1"}, j)

	if n := countPrefix(t, filepath.Join(dir, shared.StateDeferred), "qf"); n != 1 {
		t.Fatalf("expected the job to be deferred when TLS is required, found %d deferred", n)
	}
}

func TestCheckQuota(t *testing.T) {
	m := &MTA{MaxSpoolBytes: 100}
	m.spoolBytes.Store(90)
	if err := m.checkQuota(5); err != nil {
		t.Errorf("checkQuota(5) with 90/100 used = %v, want nil", err)
	}
	if err := m.checkQuota(20); err != shared.ErrSpoolFull {
		t.Errorf("checkQuota(20) with 90/100 used = %v, want ErrSpoolFull", err)
	}
	m.MaxSpoolBytes = 0
	if err := m.checkQuota(1 << 40); err != nil {
		t.Errorf("unlimited quota rejected a message: %v", err)
	}
}

func TestBounceRespectsQuota(t *testing.T) {
	dir := newSpool(t)
	m := &MTA{
		SpoolDir:      dir,
		Hostname:      "mail.test",
		MaxSpoolBytes: 1,
		log:           zap.NewNop(),
	}
	m.spoolBytes.Store(1)
	j := &shared.Job{ID: "orig", From: "a@b.com", To: []string{"c@d.com"}}
	m.failRecipients(j, j.To, "boom")
	if n := countPrefix(t, filepath.Join(dir, shared.StateIncoming), "qf"); n != 0 {
		t.Errorf("bounce bypassed the spool quota: %d queued", n)
	}
}

func TestPruneMaps(t *testing.T) {
	now := time.Now()
	m := &MTA{
		mxCache: map[string]mxCacheEntry{
			"expired": {expiry: now.Add(-time.Minute)},
			"live":    {expiry: now.Add(time.Hour)},
		},
		mxSem: map[string]mxSemEntry{
			"idle":  {sem: make(chan struct{}, 1), lastUsed: now.Add(-2 * mxSemIdleTTL)},
			"fresh": {sem: make(chan struct{}, 1), lastUsed: now},
		},
	}
	m.pruneMaps(now)
	if _, ok := m.mxCache["expired"]; ok {
		t.Error("expired MX cache entry was not evicted")
	}
	if _, ok := m.mxCache["live"]; !ok {
		t.Error("live MX cache entry was evicted")
	}
	if _, ok := m.mxSem["idle"]; ok {
		t.Error("idle MX semaphore was not evicted")
	}
	if _, ok := m.mxSem["fresh"]; !ok {
		t.Error("fresh MX semaphore was evicted")
	}

	held := make(chan struct{}, 1)
	held <- struct{}{}
	m.mxSem["held"] = mxSemEntry{sem: held, lastUsed: now.Add(-2 * mxSemIdleTTL)}
	m.pruneMaps(now)
	if _, ok := m.mxSem["held"]; !ok {
		t.Error("in-use MX semaphore was evicted")
	}
}

func TestEnqueueAddsMessageID(t *testing.T) {
	dir := newSpool(t)
	m := &MTA{SpoolDir: dir, Hostname: "mail.example"}
	env := &shared.Envelope{From: "alice@example.com", To: []string{"bob@example.com"}}
	body := []byte("From: alice@example.com\r\nSubject: hi\r\n\r\nbody")

	id, err := m.Enqueue(context.Background(), env, body)
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, shared.StateIncoming, "df"+id))
	if err != nil {
		t.Fatalf("read spooled message: %v", err)
	}
	if !shared.HasMessageID(raw) {
		t.Errorf("enqueued message has no Message-ID: %q", raw)
	}

	id, err = m.Enqueue(context.Background(), env, []byte("Message-ID: <keep@example.com>\r\n\r\nbody"))
	if err != nil {
		t.Fatalf("Enqueue: %v", err)
	}
	raw, err = os.ReadFile(filepath.Join(dir, shared.StateIncoming, "df"+id))
	if err != nil {
		t.Fatalf("read spooled message: %v", err)
	}
	if strings.Count(string(raw), "Message-ID:") != 1 || !strings.Contains(string(raw), "<keep@example.com>") {
		t.Errorf("caller-supplied Message-ID was not preserved: %q", raw)
	}
}
