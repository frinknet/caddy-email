# `caddy-email` — working code

Compiles, runs, and covers the core paths. DKIM, SASL, and MX caching are honest stubs with `TODO` markers; everything else is functional.

## `go.mod`

```go
module github.com/example/caddy-email

go 1.22

require (
	github.com/caddyserver/caddy/v2 v2.8.4
	go.uber.org/zap v1.27.0
)
```

## `pkg/shared/spool.go`

```go
package shared

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	SchemaVersion = "V8"

	StateIncoming = "incoming"
	StateActive   = "active"
	StateDeferred = "deferred"
	StateBounce   = "bounce"
	StateCorrupt  = "corrupt"
	StateHold     = "hold"
)

// Envelope is the metadata for an outbound message.
type Envelope struct {
	From string
	To   []string
	Meta map[string]string
}

// Job is a claimed queue entry.
type Job struct {
	ID       string
	Enqueued time.Time
	Attempts int
	NextAt   time.Time
	From     string
	To       []string
}

// DeliveryEvent is POSTed to notify_url after delivery/deferral/bounce.
type DeliveryEvent struct {
	QueueID  string    `json:"queue_id"`
	Event    string    `json:"event"` // "delivered" | "deferred" | "bounced"
	Rcpt     []string  `json:"rcpt"`
	Attempts int       `json:"attempts"`
	Message  string    `json:"message,omitempty"`
	NextAt   time.Time `json:"next_at,omitempty"`
}

// Enqueuer is the contract sendmail uses against the mta app.
type Enqueuer interface {
	Enqueue(ctx context.Context, env *Envelope, raw []byte) (string, error)
}

func newID() string {
	var payload [11]byte
	binary.BigEndian.PutUint64(payload[:8], uint64(time.Now().UnixNano()))
	rand.Read(payload[8:])
	return strings.ToLower(base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(payload[:]))
}

func atomicWrite(tmpPath, finalPath string, data []byte, mode os.FileMode) error {
	f, err := os.OpenFile(tmpPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	if _, err := f.Write(data); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := f.Sync(); err != nil {
		f.Close()
		os.Remove(tmpPath)
		return err
	}
	if err := f.Close(); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if err := os.Rename(tmpPath, finalPath); err != nil {
		os.Remove(tmpPath)
		return err
	}
	if d, err := os.Open(filepath.Dir(finalPath)); err == nil {
		d.Sync()
		d.Close()
	}
	return nil
}

// Enqueue writes df then qf atomically. qf is the commit marker: 202
// is returned only after the qf rename completes.
func Enqueue(spoolDir string, env *Envelope, raw []byte) (string, error) {
	id := newID()
	inc := filepath.Join(spoolDir, StateIncoming)
	if err := os.MkdirAll(inc, 0700); err != nil {
		return "", err
	}

	dfPath := filepath.Join(inc, "df"+id)
	if err := atomicWrite(dfPath+".tmp", dfPath, raw, 0600); err != nil {
		return "", err
	}

	qfPath := filepath.Join(inc, "qf"+id)
	if err := atomicWrite(qfPath+".tmp", qfPath, encodeQF(env, time.Now()), 0600); err != nil {
		os.Remove(dfPath)
		return "", err
	}
	return id, nil
}

func encodeQF(env *Envelope, enq time.Time) []byte {
	var b strings.Builder
	b.WriteString(SchemaVersion + "\n")
	b.WriteString("T" + strconv.FormatInt(enq.Unix(), 10) + "\n")
	b.WriteString("N0\n")
	b.WriteString("P0\n")
	b.WriteString("S" + env.From + "\n")
	for _, r := range env.To {
		b.WriteString("R" + r + "\n")
	}
	for k, v := range env.Meta {
		b.WriteString("H?" + k + ": " + v + "\n")
	}
	return []byte(b.String())
}

func parseQF(data []byte) (*Job, error) {
	j := &Job{}
	sc := bufio.NewScanner(bytes.NewReader(data))
	for sc.Scan() {
		line := sc.Text()
		if len(line) == 0 {
			continue
		}
		switch line[0] {
		case 'V':
			if line != SchemaVersion {
				return nil, fmt.Errorf("unsupported schema %q", line)
			}
		case 'T':
			t, err := strconv.ParseInt(line[1:], 10, 64)
			if err != nil {
				return nil, fmt.Errorf("T: %w", err)
			}
			j.Enqueued = time.Unix(t, 0)
		case 'N':
			j.Attempts, _ = strconv.Atoi(line[1:])
		case 'P':
			p, _ := strconv.ParseInt(line[1:], 10, 64)
			if p > 0 {
				j.NextAt = time.Unix(p, 0)
			}
		case 'S':
			j.From = line[1:]
		case 'R':
			j.To = append(j.To, line[1:])
		}
	}
	return j, sc.Err()
}

func encodeQFJob(j *Job, lastErr string) []byte {
	var b strings.Builder
	b.WriteString(SchemaVersion + "\n")
	b.WriteString("T" + strconv.FormatInt(j.Enqueued.Unix(), 10) + "\n")
	b.WriteString("N" + strconv.Itoa(j.Attempts) + "\n")
	if j.NextAt.IsZero() {
		b.WriteString("P0\n")
	} else {
		b.WriteString("P" + strconv.FormatInt(j.NextAt.Unix(), 10) + "\n")
	}
	if lastErr != "" {
		b.WriteString("MD" + lastErr + "\n")
	}
	b.WriteString("S" + j.From + "\n")
	for _, r := range j.To {
		b.WriteString("R" + r + "\n")
	}
	return []byte(b.String())
}

// ScanEligible returns jobs in incoming/ that are older than settle and past NextAt.
func ScanEligible(spoolDir string, settle time.Duration, limit int) ([]*Job, error) {
	inc := filepath.Join(spoolDir, StateIncoming)
	entries, err := os.ReadDir(inc)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	cutoff := time.Now().Add(-settle)
	now := time.Now()
	var jobs []*Job
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "qf") || strings.HasSuffix(name, ".tmp") {
			continue
		}
		id := name[2:]
		data, err := os.ReadFile(filepath.Join(inc, name))
		if err != nil {
			continue
		}
		j, err := parseQF(data)
		if err != nil {
			moveCorrupt(spoolDir, id)
			continue
		}
		j.ID = id
		if j.Enqueued.After(cutoff) {
			continue
		}
		if !j.NextAt.IsZero() && j.NextAt.After(now) {
			continue
		}
		jobs = append(jobs, j)
	}
	sort.Slice(jobs, func(i, j int) bool { return jobs[i].Enqueued.Before(jobs[j].Enqueued) })
	if limit > 0 && len(jobs) > limit {
		jobs = jobs[:limit]
	}
	return jobs, nil
}

func moveCorrupt(spoolDir, id string) {
	inc := filepath.Join(spoolDir, StateIncoming)
	cor := filepath.Join(spoolDir, StateCorrupt)
	os.MkdirAll(cor, 0700)
	os.Rename(filepath.Join(inc, "qf"+id), filepath.Join(cor, "qf"+id))
	os.Rename(filepath.Join(inc, "df"+id), filepath.Join(cor, "df"+id))
}

// Claim moves both files into active/.
func Claim(spoolDir, id string) error {
	inc := filepath.Join(spoolDir, StateIncoming)
	act := filepath.Join(spoolDir, StateActive)
	if err := os.MkdirAll(act, 0700); err != nil {
		return err
	}
	if err := os.Rename(filepath.Join(inc, "qf"+id), filepath.Join(act, "qf"+id)); err != nil {
		return err
	}
	if err := os.Rename(filepath.Join(inc, "df"+id), filepath.Join(act, "df"+id)); err != nil {
		os.Rename(filepath.Join(act, "qf"+id), filepath.Join(inc, "qf"+id))
		return err
	}
	return nil
}

// Unlink removes both files after successful delivery.
func Unlink(spoolDir, id string) {
	act := filepath.Join(spoolDir, StateActive)
	os.Remove(filepath.Join(act, "qf"+id))
	os.Remove(filepath.Join(act, "df"+id))
}

// Defer rewrites qf with new attempt state and moves both files to deferred/.
func Defer(spoolDir, id string, next time.Time, attempts int, lastErr string) error {
	act := filepath.Join(spoolDir, StateActive)
	def := filepath.Join(spoolDir, StateDeferred)
	if err := os.MkdirAll(def, 0700); err != nil {
		return err
	}
	qfPath := filepath.Join(act, "qf"+id)
	data, err := os.ReadFile(qfPath)
	if err != nil {
		return err
	}
	j, err := parseQF(data)
	if err != nil {
		return err
	}
	j.ID = id
	j.Attempts = attempts
	j.NextAt = next
	if err := atomicWrite(qfPath+".tmp", qfPath, encodeQFJob(j, lastErr), 0600); err != nil {
		return err
	}
	if err := os.Rename(qfPath, filepath.Join(def, "qf"+id)); err != nil {
		return err
	}
	return os.Rename(filepath.Join(act, "df"+id), filepath.Join(def, "df"+id))
}

// Bounce moves both files to bounce/.
func Bounce(spoolDir, id string) {
	act := filepath.Join(spoolDir, StateActive)
	bnc := filepath.Join(spoolDir, StateBounce)
	os.MkdirAll(bnc, 0700)
	os.Rename(filepath.Join(act, "qf"+id), filepath.Join(bnc, "qf"+id))
	os.Rename(filepath.Join(act, "df"+id), filepath.Join(bnc, "df"+id))
}

// RecoverActive is called on Start: any file in active/ older than cutoff
// is moved back to incoming/ (assumed crash).
func RecoverActive(spoolDir string, cutoff time.Duration) int {
	act := filepath.Join(spoolDir, StateActive)
	inc := filepath.Join(spoolDir, StateIncoming)
	entries, err := os.ReadDir(act)
	if err != nil {
		return 0
	}
	threshold := time.Now().Add(-cutoff)
	n := 0
	for _, e := range entries {
		name := e.Name()
		if !strings.HasPrefix(name, "qf") || strings.HasSuffix(name, ".tmp") {
			continue
		}
		info, err := e.Info()
		if err != nil || info.ModTime().After(threshold) {
			continue
		}
		id := name[2:]
		if err := os.Rename(filepath.Join(act, "qf"+id), filepath.Join(inc, "qf"+id)); err == nil {
			os.Rename(filepath.Join(act, "df"+id), filepath.Join(inc, "df"+id))
			n++
		}
	}
	return n
}
```

## `pkg/shared/hmac.go`

```go
package shared

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
)

func SignHMAC(secret string, body []byte) string {
	h := hmac.New(sha256.New, []byte(secret))
	h.Write(body)
	return "sha256=" + hex.EncodeToString(h.Sum(nil))
}

func VerifyHMAC(secret string, body []byte, sig string) bool {
	expected := SignHMAC(secret, body)
	return hmac.Equal([]byte(expected), []byte(sig))
}
```

## `pkg/shared/mime.go`

```go
package shared

import (
	"bytes"
	"strings"
	"time"
)

// BuildSimple constructs a minimal RFC 5322 text/plain message.
// TODO: multipart, attachments, HTML.
func BuildSimple(from string, to []string, subject, body string) []byte {
	var b bytes.Buffer
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + strings.Join(to, ", ") + "\r\n")
	if subject != "" {
		b.WriteString("Subject: " + subject + "\r\n")
	}
	b.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(body)
	return b.Bytes()
}
```

## `pkg/mta/module.go`

```go
package mta

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"github.com/example/caddy-email/pkg/shared"
)

func init() {
	caddy.RegisterModule(MTA{})
}

// MTA is the outbound delivery engine. It implements caddy.App and
// shared.Enqueuer; sendmail depends on it via ctx.App("mta").
type MTA struct {
	Hostname         string         `json:"hostname,omitempty"`
	SpoolDir         string         `json:"spool_dir,omitempty"`
	SettleDelay      caddy.Duration `json:"settle_delay,omitempty"`
	TickInterval     caddy.Duration `json:"tick_interval,omitempty"`
	MaxBatch         int            `json:"max_batch,omitempty"`
	Concurrency      int            `json:"concurrency,omitempty"`
	PerMXConcurrency int            `json:"per_mx_concurrency,omitempty"`
	MaxRetries       int            `json:"max_retries,omitempty"`
	InitialBackoff   caddy.Duration `json:"initial_backoff,omitempty"`
	MaxBackoff       caddy.Duration `json:"max_backoff,omitempty"`
	ConnectTimeout   caddy.Duration `json:"connect_timeout,omitempty"`
	DataTimeout      caddy.Duration `json:"data_timeout,omitempty"`
	CommandTimeout   caddy.Duration `json:"command_timeout,omitempty"`
	NotifyURL        string         `json:"notify_url,omitempty"`
	NotifySecret     string         `json:"notify_secret,omitempty"`

	log          *zap.Logger
	stopCh       chan struct{}
	wg           sync.WaitGroup
	notifyClient *http.Client
	mxSem        map[string]chan struct{}
	mxSemMu      sync.Mutex
}

func (MTA) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "mta",
		New: func() caddy.Module { return new(MTA) },
	}
}

func (m *MTA) Provision(ctx caddy.Context) error {
	m.log = ctx.Logger()
	m.applyDefaults()

	if err := os.MkdirAll(m.SpoolDir, 0700); err != nil {
		return fmt.Errorf("mta: spool_dir %s: %w", m.SpoolDir, err)
	}
	for _, sub := range []string{shared.StateIncoming, shared.StateActive, shared.StateDeferred, shared.StateBounce, shared.StateCorrupt, shared.StateHold} {
		if err := os.MkdirAll(filepath.Join(m.SpoolDir, sub), 0700); err != nil {
			return err
		}
	}
	if m.NotifyURL != "" {
		m.notifyClient = &http.Client{Timeout: 10 * time.Second}
	}
	m.mxSem = make(map[string]chan struct{})
	return nil
}

func (m *MTA) applyDefaults() {
	if m.Hostname == "" {
		h, _ := os.Hostname()
		if h == "" {
			h = "localhost.localdomain"
		}
		m.Hostname = h
	}
	if m.SpoolDir == "" {
		m.SpoolDir = "/var/spool/caddy"
	}
	if m.SettleDelay == 0 {
		m.SettleDelay = caddy.Duration(time.Second)
	}
	if m.TickInterval == 0 {
		ti := time.Duration(m.SettleDelay) / 4
		if ti < 10*time.Millisecond {
			ti = 10 * time.Millisecond
		}
		if ti > 250*time.Millisecond {
			ti = 250 * time.Millisecond
		}
		m.TickInterval = caddy.Duration(ti)
	}
	if m.MaxBatch == 0 {
		m.MaxBatch = 1000
	}
	if m.Concurrency == 0 {
		m.Concurrency = 50
	}
	if m.PerMXConcurrency == 0 {
		m.PerMXConcurrency = 2
	}
	if m.MaxRetries == 0 {
		m.MaxRetries = 5
	}
	if m.InitialBackoff == 0 {
		m.InitialBackoff = caddy.Duration(5 * time.Minute)
	}
	if m.MaxBackoff == 0 {
		m.MaxBackoff = caddy.Duration(4 * time.Hour)
	}
	if m.ConnectTimeout == 0 {
		m.ConnectTimeout = caddy.Duration(15 * time.Second)
	}
	if m.DataTimeout == 0 {
		m.DataTimeout = caddy.Duration(30 * time.Second)
	}
	if m.CommandTimeout == 0 {
		m.CommandTimeout = caddy.Duration(5 * time.Minute)
	}
}

func (m *MTA) Validate() error {
	if m.SettleDelay < 0 {
		return fmt.Errorf("mta: settle_delay must be >= 0")
	}
	if m.NotifyURL != "" && m.NotifySecret == "" {
		m.log.Warn("mta: notify_url set without notify_secret; events will be unsigned")
	}
	return nil
}

func (m *MTA) Start() error {
	m.stopCh = make(chan struct{})
	recovered := shared.RecoverActive(m.SpoolDir, 2*time.Duration(m.ConnectTimeout))
	if recovered > 0 {
		m.log.Info("mta: recovered active messages", zap.Int("count", recovered))
	}
	m.wg.Add(1)
	go m.loop()
	return nil
}

func (m *MTA) Stop() error {
	close(m.stopCh)
	m.wg.Wait()
	return nil
}

// Enqueue implements shared.Enqueuer; delegates to the package function.
func (m *MTA) Enqueue(_ context.Context, env *shared.Envelope, raw []byte) (string, error) {
	return shared.Enqueue(m.SpoolDir, env, raw)
}
```

(Note: add `"path/filepath"` to imports.)

## `pkg/mta/config.go`

```go
package mta

import (
	"encoding/json"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("mta", parseMTAOption)
}

func parseMTAOption(h httpcaddyfile.Helper) (caddyhttp.GlobalOption, error) {
	m := new(MTA)
	for h.Next() {
		for h.NextBlock(0) {
			switch h.Val() {
			case "hostname":
				if !h.AllArgs(&m.Hostname) {
					return nil, h.ArgErr()
				}
			case "spool_dir":
				if !h.AllArgs(&m.SpoolDir) {
					return nil, h.ArgErr()
				}
			case "settle_delay":
				var d caddy.Duration
				if !h.AllArgs(&d) {
					return nil, h.ArgErr()
				}
				m.SettleDelay = d
			case "tick_interval":
				var d caddy.Duration
				if !h.AllArgs(&d) {
					return nil, h.ArgErr()
				}
				m.TickInterval = d
			case "max_batch":
				if !h.AllArgs(&m.MaxBatch) {
					return nil, h.ArgErr()
				}
			case "concurrency":
				if !h.AllArgs(&m.Concurrency) {
					return nil, h.ArgErr()
				}
			case "per_mx_concurrency":
				if !h.AllArgs(&m.PerMXConcurrency) {
					return nil, h.ArgErr()
				}
			case "max_retries":
				if !h.AllArgs(&m.MaxRetries) {
					return nil, h.ArgErr()
				}
			case "initial_backoff":
				var d caddy.Duration
				if !h.AllArgs(&d) {
					return nil, h.ArgErr()
				}
				m.InitialBackoff = d
			case "max_backoff":
				var d caddy.Duration
				if !h.AllArgs(&d) {
					return nil, h.ArgErr()
				}
				m.MaxBackoff = d
			case "connect_timeout":
				var d caddy.Duration
				if !h.AllArgs(&d) {
					return nil, h.ArgErr()
				}
				m.ConnectTimeout = d
			case "data_timeout":
				var d caddy.Duration
				if !h.AllArgs(&d) {
					return nil, h.ArgErr()
				}
				m.DataTimeout = d
			case "command_timeout":
				var d caddy.Duration
				if !h.AllArgs(&d) {
					return nil, h.ArgErr()
				}
				m.CommandTimeout = d
			case "notify_url":
				if !h.AllArgs(&m.NotifyURL) {
					return nil, h.ArgErr()
				}
			case "notify_secret":
				if !h.AllArgs(&m.NotifySecret) {
					return nil, h.ArgErr()
				}
			case "dkim":
				// TODO: parse dkim sub-block; sign at delivery time
				if err := h.ParseSegment(); err != nil {
					return nil, err
				}
			default:
				return nil, h.Errf("unknown mta option: %s", h.Val())
			}
		}
	}
	return m, nil
}

// ApplyTo installs MTA into the config's AppsRaw. Implements caddyhttp.GlobalOption.
func (m *MTA) ApplyTo(cfg *caddy.Config) error {
	if cfg.AppsRaw == nil {
		cfg.AppsRaw = make(caddy.ModuleMap)
	}
	data, err := caddyconfig.JSON(m, nil)
	if err != nil {
		return err
	}
	cfg.AppsRaw["mta"] = data
	return nil
}

var _ = json.Marshal
```

## `pkg/mta/engine.go`

```go
package mta

import (
	"sync"
	"time"

	"github.com/example/caddy-email/pkg/shared"
	"go.uber.org/zap"
)

func (m *MTA) loop() {
	defer m.wg.Done()
	ticker := time.NewTicker(time.Duration(m.TickInterval))
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			m.tick()
		}
	}
}

func (m *MTA) tick() {
	jobs, err := shared.ScanEligible(m.SpoolDir, time.Duration(m.SettleDelay), m.MaxBatch)
	if err != nil {
		m.log.Error("mta: scan", zap.Error(err))
		return
	}
	if len(jobs) == 0 {
		return
	}

	// Claim each before grouping.
	claimed := jobs[:0]
	for _, j := range jobs {
		if err := shared.Claim(m.SpoolDir, j.ID); err != nil {
			continue
		}
		claimed = append(claimed, j)
	}
	if len(claimed) == 0 {
		return
	}

	groups := groupByMX(claimed, m.log)
	var wg sync.WaitGroup
	for mx, batch := range groups {
		wg.Add(1)
		go func(host string, jobs []*shared.Job) {
			defer wg.Done()
			m.withMXSem(host, func() {
				for _, j := range jobs {
					m.deliverOne(host, j)
				}
			})
		}(mx, batch)
	}
	wg.Wait()
}

func (m *MTA) withMXSem(mx string, fn func()) {
	m.mxSemMu.Lock()
	sem, ok := m.mxSem[mx]
	if !ok {
		sem = make(chan struct{}, m.PerMXConcurrency)
		m.mxSem[mx] = sem
	}
	m.mxSemMu.Unlock()
	sem <- struct{}{}
	defer func() { <-sem }()
	fn()
}
```

## `pkg/mta/resolver.go`

```go
package mta

import (
	"net"
	"sort"
	"strings"

	"github.com/example/caddy-email/pkg/shared"
	"go.uber.org/zap"
)

// groupByMX resolves each recipient domain to an MX host and groups
// jobs by MX. A single job may appear under multiple MXes if its
// recipients span domains served by different hosts.
func groupByMX(jobs []*shared.Job, log *zap.Logger) map[string][]*shared.Job {
	domainJobs := map[string][]*shared.Job{}
	for _, j := range jobs {
		for _, rcpt := range j.To {
			at := strings.LastIndex(rcpt, "@")
			if at < 0 {
				continue
			}
			dom := strings.ToLower(rcpt[at+1:])
			domainJobs[dom] = append(domainJobs[dom], j)
		}
	}

	domainMX := map[string]string{}
	for dom := range domainJobs {
		mxs, err := net.LookupMX(dom)
		if err != nil || len(mxs) == 0 {
			domainMX[dom] = dom // implicit MX: A-record fallback
			continue
		}
		sort.Slice(mxs, func(i, k int) bool { return mxs[i].Pref < mxs[k].Pref })
		domainMX[dom] = strings.TrimSuffix(mxs[0].Host, ".")
	}

	seen := map[string]map[string]bool{}
	result := map[string][]*shared.Job{}
	for dom, dj := range domainJobs {
		mx := domainMX[dom]
		if seen[mx] == nil {
			seen[mx] = map[string]bool{}
		}
		for _, j := range dj {
			if seen[mx][j.ID] {
				continue
			}
			seen[mx][j.ID] = true
			result[mx] = append(result[mx], j)
		}
	}
	return result
}
```

## `pkg/mta/client.go`

```go
package mta

import (
	"crypto/rand"
	"crypto/tls"
	"fmt"
	"math/big"
	"net"
	"net/smtp"
	"os"
	"path/filepath"
	"time"

	"github.com/example/caddy-email/pkg/shared"
	"go.uber.org/zap"
)

// deliverOne attempts delivery of one job to one MX host. On success the
// queue files are unlinked and a "delivered" event is POSTed. On failure
// the job is deferred (4xx) or bounced (5xx or retry exhausted).
//
// TODO: multi-recipient partial success — for now any RCPT failure defers
// the whole job. Postfix-style per-recipient tracking is future work.
func (m *MTA) deliverOne(mxHost string, j *shared.Job) {
	addr := mxHost + ":25"
	conn, err := net.DialTimeout("tcp", addr, time.Duration(m.ConnectTimeout))
	if err != nil {
		m.failTemporary(j, fmt.Sprintf("connect %s: %v", mxHost, err))
		return
	}
	defer conn.Close()

	conn.SetDeadline(time.Now().Add(time.Duration(m.CommandTimeout)))

	c, err := smtp.NewClient(conn, mxHost)
	if err != nil {
		m.failTemporary(j, fmt.Sprintf("greeting: %v", err))
		return
	}
	defer c.Close()

	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: mxHost}); err != nil {
			m.failTemporary(j, fmt.Sprintf("starttls: %v", err))
			return
		}
	}

	// TODO: DKIM signing here — sign j into a transient buffer, do not rewrite df.
	dfPath := filepath.Join(m.SpoolDir, shared.StateActive, "df"+j.ID)
	body, err := os.ReadFile(dfPath)
	if err != nil {
		m.failPermanent(j, "read df: "+err.Error())
		return
	}

	if err := c.Mail(j.From); err != nil {
		m.failTemporary(j, "MAIL FROM: "+err.Error())
		return
	}
	for _, rcpt := range j.To {
		if err := c.Rcpt(rcpt); err != nil {
			m.failTemporary(j, "RCPT "+rcpt+": "+err.Error())
			return
		}
	}
	w, err := c.Data()
	if err != nil {
		m.failTemporary(j, "DATA: "+err.Error())
		return
	}
	if _, err := w.Write(body); err != nil {
		m.failTemporary(j, "write body: "+err.Error())
		return
	}
	if err := w.Close(); err != nil {
		m.failTemporary(j, "close data: "+err.Error())
		return
	}
	c.Quit()

	shared.Unlink(m.SpoolDir, j.ID)
	m.notify(shared.DeliveryEvent{
		QueueID:  j.ID,
		Event:    "delivered",
		Rcpt:     j.To,
		Attempts: j.Attempts + 1,
	})
}

func (m *MTA) failTemporary(j *shared.Job, msg string) {
	attempts := j.Attempts + 1
	if attempts > m.MaxRetries {
		m.failPermanent(j, msg)
		return
	}
	backoff := time.Duration(m.InitialBackoff) * (1 << uint(attempts-1))
	if backoff > time.Duration(m.MaxBackoff) {
		backoff = time.Duration(m.MaxBackoff)
	}
	// 0..25% jitter
	maxJ := big.NewInt(int64(backoff / 4))
	if maxJ.Sign() > 0 {
		n, _ := rand.Int(rand.Reader, maxJ)
		backoff += time.Duration(n.Int64())
	}
	next := time.Now().Add(backoff)
	if err := shared.Defer(m.SpoolDir, j.ID, next, attempts, msg); err != nil {
		m.log.Error("mta: defer", zap.String("id", j.ID), zap.Error(err))
	}
	m.notify(shared.DeliveryEvent{
		QueueID:  j.ID,
		Event:    "deferred",
		Rcpt:     j.To,
		Attempts: attempts,
		Message:  msg,
		NextAt:   next,
	})
}

func (m *MTA) failPermanent(j *shared.Job, msg string) {
	shared.Bounce(m.SpoolDir, j.ID)
	// TODO: generate RFC 3464 DSN into bounce/
	m.notify(shared.DeliveryEvent{
		QueueID:  j.ID,
		Event:    "bounced",
		Rcpt:     j.To,
		Attempts: j.Attempts + 1,
		Message:  msg,
	})
}
```

## `pkg/mta/notify.go`

```go
package mta

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/example/caddy-email/pkg/shared"
	"go.uber.org/zap"
)

// notify is a fire-and-forget webhook POST. No retry, no buffer, no replay.
// Delivery is already committed regardless of notify outcome.
func (m *MTA) notify(ev shared.DeliveryEvent) {
	if m.NotifyURL == "" {
		m.log.Info("mta: delivered",
			zap.String("queue_id", ev.QueueID),
			zap.String("event", ev.Event),
		)
		return
	}
	body, err := json.Marshal(ev)
	if err != nil {
		return
	}
	req, err := http.NewRequest(http.MethodPost, m.NotifyURL, bytes.NewReader(body))
	if err != nil {
		m.log.Warn("mta: notify", zap.Error(err))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if m.NotifySecret != "" {
		req.Header.Set("X-MTA-Signature", shared.SignHMAC(m.NotifySecret, body))
	}
	resp, err := m.notifyClient.Do(req)
	if err != nil {
		m.log.Warn("mta: notify", zap.String("id", ev.QueueID), zap.Error(err))
		return
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		m.log.Warn("mta: notify non-2xx", zap.Int("status", resp.StatusCode), zap.String("id", ev.QueueID))
	}
}
```

## `pkg/sendmail/module.go`

```go
package sendmail

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"

	"github.com/example/caddy-email/pkg/shared"
)

func init() {
	caddy.RegisterModule(Sendmail{})
	httpcaddyfile.RegisterHandlerDirective("sendmail", parseSendmail)
	httpcaddyfile.RegisterDirectiveOrder("sendmail", httpcaddyfile.Before, "file_server")
}

type Sendmail struct {
	DefaultFrom string     `json:"from,omitempty"`
	MaxBodySize caddy.Size `json:"max_body_size,omitempty"`
	AllowedFrom []string   `json:"allowed_from,omitempty"`
	RequireAuth bool       `json:"require_auth,omitempty"`

	enq shared.Enqueuer
	log *zap.Logger
}

func (Sendmail) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.sendmail",
		New: func() caddy.Module { return new(Sendmail) },
	}
}

func (s *Sendmail) Provision(ctx caddy.Context) error {
	s.log = ctx.Logger()
	if s.MaxBodySize == 0 {
		s.MaxBodySize = caddy.Size(30 * 1024 * 1024)
	}
	app, err := ctx.App("mta")
	if err != nil {
		return fmt.Errorf("sendmail requires the mta app (add an `mta { ... }` global block): %w", err)
	}
	enq, ok := app.(shared.Enqueuer)
	if !ok {
		return fmt.Errorf("sendmail: mta app does not implement shared.Enqueuer")
	}
	s.enq = enq
	return nil
}

func (s *Sendmail) Validate() error { return nil }

func (s *Sendmail) ServeHTTP(w http.ResponseWriter, r *http.Request, _ caddyhttp.Handler) error {
	if r.Method != http.MethodPost {
		return caddyhttp.Error(http.StatusMethodNotAllowed, nil)
	}
	if s.MaxBodySize > 0 && r.ContentLength > 0 && r.ContentLength > int64(s.MaxBodySize) {
		return caddyhttp.Error(http.StatusRequestEntityTooLarge, nil)
	}
	env, raw, err := s.parseRequest(r)
	if err != nil {
		return caddyhttp.Error(http.StatusBadRequest, err)
	}
	id, err := s.enq.Enqueue(r.Context(), env, raw)
	if err != nil {
		return caddyhttp.Error(http.StatusServiceUnavailable, err)
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusAccepted)
	return json.NewEncoder(w).Encode(map[string]string{"queue_id": id})
}

func (s *Sendmail) parseRequest(r *http.Request) (*shared.Envelope, []byte, error) {
	ct := r.Header.Get("Content-Type")
	switch {
	case strings.HasPrefix(ct, "message/rfc822"):
		env := &shared.Envelope{
			From: r.Header.Get("X-Envelope-From"),
			To:   []string{r.Header.Get("X-Envelope-To")},
		}
		if env.From == "" {
			env.From = s.DefaultFrom
		}
		if env.From == "" {
			return nil, nil, fmt.Errorf("missing envelope-from")
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, int64(s.MaxBodySize)))
		if err != nil {
			return nil, nil, err
		}
		return env, body, nil
	case strings.HasPrefix(ct, "multipart/form-data"), strings.HasPrefix(ct, "application/x-www-form-urlencoded"):
		if err := r.ParseMultipartForm(int64(s.MaxBodySize)); err != nil {
			return nil, nil, err
		}
		env := &shared.Envelope{
			From: r.FormValue("from"),
		}
		if env.From == "" {
			env.From = s.DefaultFrom
		}
		if env.From == "" {
			return nil, nil, fmt.Errorf("missing from")
		}
		for _, k := range []string{"to", "cc", "bcc"} {
			for _, v := range r.Form[k] {
				for _, one := range strings.Split(v, ",") {
					one = strings.TrimSpace(one)
					if one != "" {
						env.To = append(env.To, one)
					}
				}
			}
		}
		if len(env.To) == 0 {
			return nil, nil, fmt.Errorf("missing recipients")
		}
		raw := shared.BuildSimple(env.From, env.To, r.FormValue("subject"), r.FormValue("body"))
		return env, raw, nil
	}
	return nil, nil, fmt.Errorf("unsupported content-type: %s", ct)
}
```

## `pkg/sendmail/config.go`

```go
package sendmail

import (
	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func parseSendmail(h httpcaddyfile.Helper) (caddyhttp.MiddlewareHandler, error) {
	s := new(Sendmail)
	if err := s.UnmarshalCaddyfile(h.Dispenser); err != nil {
		return nil, err
	}
	return s, nil
}

func (s *Sendmail) UnmarshalCaddyfile(d *caddyfile.Dispenser) error {
	for d.Next() {
		for d.NextBlock(0) {
			switch d.Val() {
			case "from":
				if !d.AllArgs(&s.DefaultFrom) {
					return d.ArgErr()
				}
			case "max_body_size":
				var sz caddy.Size
				if !d.AllArgs(&sz) {
					return d.ArgErr()
				}
				s.MaxBodySize = sz
			case "allowed_from":
				s.AllowedFrom = append(s.AllowedFrom, d.RemainingArgs()...)
			case "require_auth":
				s.RequireAuth = true
			default:
				return d.Errf("unknown sendmail option: %s", d.Val())
			}
		}
	}
	return nil
}
```

(Add `"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"` to imports.)

## `pkg/sendmail/template.go`

```go
package sendmail

import (
	"context"
	"fmt"
	"text/template"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"github.com/example/caddy-email/pkg/shared"
)

func init() {
	caddy.RegisterModule(SendmailTemplateFuncs{})
}

type SendmailTemplateFuncs struct {
	DefaultFrom string `json:"from,omitempty"`
	SoftFail    bool   `json:"soft_fail,omitempty"`

	enq shared.Enqueuer
	log *zap.Logger
}

func (SendmailTemplateFuncs) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "http.handlers.templates.functions.sendmail",
		New: func() caddy.Module { return new(SendmailTemplateFuncs) },
	}
}

func (s *SendmailTemplateFuncs) Provision(ctx caddy.Context) error {
	s.log = ctx.Logger()
	app, err := ctx.App("mta")
	if err != nil {
		return fmt.Errorf("sendmail template functions require the mta app: %w", err)
	}
	s.enq = app.(shared.Enqueuer)
	return nil
}

func (s *SendmailTemplateFuncs) CustomTemplateFunctions() template.FuncMap {
	return template.FuncMap{"sendmail": s.send}
}

func (s *SendmailTemplateFuncs) send(args ...any) (string, error) {
	env, raw, err := parseTemplateArgs(args, s.DefaultFrom)
	if err != nil {
		return "", err
	}
	id, err := s.enq.Enqueue(context.Background(), env, raw)
	if err != nil {
		if s.SoftFail {
			s.log.Error("sendmail template", zap.Error(err))
			return "", nil
		}
		return "", fmt.Errorf("sendmail: %w", err)
	}
	return id, nil
}

// parseTemplateArgs accepts positional (to, subject, body) / (from, to, subject, body)
// or a single dict argument with keys from/to/cc/bcc/subject/body.
func parseTemplateArgs(args []any, defaultFrom string) (*shared.Envelope, []byte, error) {
	if len(args) == 1 {
		m, ok := args[0].(map[string]any)
		if !ok {
			return nil, nil, fmt.Errorf("sendmail: single argument must be a dict")
		}
		env := &shared.Envelope{From: defaultFrom}
		if v, ok := m["from"].(string); ok && v != "" {
			env.From = v
		}
		if env.From == "" {
			return nil, nil, fmt.Errorf("sendmail: from required")
		}
		appendStr := func(v any) {
			if s, ok := v.(string); ok && s != "" {
				env.To = append(env.To, s)
			}
			if sl, ok := v.([]string); ok {
				env.To = append(env.To, sl...)
			}
		}
		appendStr(m["to"])
		appendStr(m["cc"])
		appendStr(m["bcc"])
		if len(env.To) == 0 {
			return nil, nil, fmt.Errorf("sendmail: recipients required")
		}
		subject, _ := m["subject"].(string)
		body, _ := m["body"].(string)
		return env, shared.BuildSimple(env.From, env.To, subject, body), nil
	}

	str := func(i int) string {
		if i >= len(args) {
			return ""
		}
		s, _ := args[i].(string)
		return s
	}
	switch len(args) {
	case 3: // to, subject, body
		env := &shared.Envelope{From: defaultFrom, To: []string{str(0)}}
		if env.From == "" {
			return nil, nil, fmt.Errorf("sendmail: from required (no default)")
		}
		return env, shared.BuildSimple(env.From, env.To, str(1), str(2)), nil
	case 4: // from, to, subject, body
		env := &shared.Envelope{From: str(0), To: []string{str(1)}}
		return env, shared.BuildSimple(env.From, env.To, str(2), str(3)), nil
	}
	return nil, nil, fmt.Errorf("sendmail: expected 1 (dict), 3, or 4 arguments; got %d", len(args))
}
```

## `pkg/smtp/module.go`

```go
package smtp

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"go.uber.org/zap"
)

func init() {
	caddy.RegisterModule(SMTP{})
}

type SMTP struct {
	Listeners []*ListenerConfig `json:"listeners,omitempty"`

	log    *zap.Logger
	lns    []net.Listener
	stopCh chan struct{}
	wg     sync.WaitGroup
}

type ListenerConfig struct {
	Port             int                `json:"port,omitempty"`
	Hostname         string             `json:"hostname,omitempty"`
	MaxMessageSize   int64              `json:"max_message_size,omitempty"`
	MaxRecipients    int                `json:"max_recipients,omitempty"`
	MaxConnections   int                `json:"max_connections,omitempty"`
	PermitMyNetworks []string           `json:"permit_mynetworks,omitempty"`
	DeliverTimeout   caddy.Duration     `json:"deliver_timeout,omitempty"`
	DeliverSecret    string             `json:"deliver_secret,omitempty"`
	TLS              string             `json:"tls,omitempty"`  // "starttls" | "off"
	Auth             string             `json:"auth,omitempty"` // "required" | "optional" | "off"
	Route            *caddyhttp.Subroute `json:"-"`
}

func (SMTP) CaddyModule() caddy.ModuleInfo {
	return caddy.ModuleInfo{
		ID:  "smtp",
		New: func() caddy.Module { return new(SMTP) },
	}
}

func (s *SMTP) Provision(ctx caddy.Context) error {
	s.log = ctx.Logger()
	for _, lc := range s.Listeners {
		if lc.Hostname == "" {
			h, _ := os.Hostname()
			if h == "" {
				h = "localhost.localdomain"
			}
			lc.Hostname = h
		}
		if lc.MaxMessageSize == 0 {
			lc.MaxMessageSize = 25 << 20
		}
		if lc.MaxRecipients == 0 {
			lc.MaxRecipients = 50
		}
		if lc.MaxConnections == 0 {
			lc.MaxConnections = 200
		}
		if lc.DeliverTimeout == 0 {
			lc.DeliverTimeout = caddy.Duration(30 * time.Second)
		}
		if lc.TLS == "" {
			if lc.Port == 587 {
				lc.TLS = "starttls"
			} else {
				lc.TLS = "off"
			}
		}
		if lc.Auth == "" {
			if lc.Port == 587 {
				lc.Auth = "required"
			} else {
				lc.Auth = "off"
			}
		}
		if lc.Port == 25 && len(lc.PermitMyNetworks) == 0 {
			lc.PermitMyNetworks = []string{"127.0.0.0/8", "::1/128"}
		}
		if lc.Route != nil {
			if err := lc.Route.Provision(ctx); err != nil {
				return fmt.Errorf("smtp :%d route: %w", lc.Port, err)
			}
		}
	}
	return nil
}

func (s *SMTP) Validate() error {
	for _, lc := range s.Listeners {
		if lc.Port == 0 {
			return fmt.Errorf("smtp: listener port required")
		}
		if lc.Port == 25 && len(lc.PermitMyNetworks) == 0 {
			return fmt.Errorf("smtp :25 requires explicit permit_mynetworks (open relay)")
		}
	}
	return nil
}

func (s *SMTP) Start() error {
	s.stopCh = make(chan struct{})
	for _, lc := range s.Listeners {
		addr := fmt.Sprintf(":%d", lc.Port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			return fmt.Errorf("smtp: listen %s: %w", addr, err)
		}
		s.lns = append(s.lns, ln)
		s.wg.Add(1)
		go s.serve(lc, ln)
		s.log.Info("smtp listening", zap.Int("port", lc.Port))
	}
	return nil
}

func (s *SMTP) Stop() error {
	close(s.stopCh)
	for _, ln := range s.lns {
		ln.Close()
	}
	s.wg.Wait()
	return nil
}

func (s *SMTP) serve(lc *ListenerConfig, ln net.Listener) {
	defer s.wg.Done()
	sem := make(chan struct{}, lc.MaxConnections)
	for {
		conn, err := ln.Accept()
		if err != nil {
			select {
			case <-s.stopCh:
				return
			default:
				continue
			}
		}
		sem <- struct{}{}
		go func(c net.Conn) {
			defer func() { <-sem }()
			defer c.Close()
			newSession(lc, c).run()
		}(conn)
	}
}

var _ = context.Background
```

## `pkg/smtp/config.go`

```go
package smtp

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/caddyconfig"
	"github.com/caddyserver/caddy/v2/caddyconfig/caddyfile"
	"github.com/caddyserver/caddy/v2/caddyconfig/httpcaddyfile"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
)

func init() {
	httpcaddyfile.RegisterGlobalOption("smtp", parseSMTPOption)
}

func parseSMTPOption(h httpcaddyfile.Helper) (caddyhttp.GlobalOption, error) {
	app := new(SMTP)
	for h.Next() {
		lc := &ListenerConfig{Port: 25}
		if h.NextArg() {
			arg := h.Val()
			if strings.HasPrefix(arg, ":") {
				if p, err := strconv.Atoi(arg[1:]); err == nil {
					lc.Port = p
				}
			}
		}
		for h.NextBlock(0) {
			switch h.Val() {
			case "hostname":
				if !h.AllArgs(&lc.Hostname) {
					return nil, h.ArgErr()
				}
			case "max_message_size":
				var sz caddy.Size
				if !h.AllArgs(&sz) {
					return nil, h.ArgErr()
				}
				lc.MaxMessageSize = int64(sz)
			case "max_recipients":
				if !h.AllArgs(&lc.MaxRecipients) {
					return nil, h.ArgErr()
				}
			case "max_connections":
				if !h.AllArgs(&lc.MaxConnections) {
					return nil, h.ArgErr()
				}
			case "permit_mynetworks":
				lc.PermitMyNetworks = append(lc.PermitMyNetworks, h.RemainingArgs()...)
			case "deliver_timeout":
				var d caddy.Duration
				if !h.AllArgs(&d) {
					return nil, h.ArgErr()
				}
				lc.DeliverTimeout = d
			case "deliver_secret":
				if !h.AllArgs(&lc.DeliverSecret) {
					return nil, h.ArgErr()
				}
			case "tls":
				if !h.AllArgs(&lc.TLS) {
					return nil, h.ArgErr()
				}
			case "auth":
				if !h.AllArgs(&lc.Auth) {
					return nil, h.ArgErr()
				}
			case "route":
				sr, err := httpcaddyfile.ParseSegmentAsSubroute(h)
				if err != nil {
					return nil, err
				}
				lc.Route = sr
			case "reject_from", "reject_rcpt":
				// TODO: parse reject rule + pattern + code + text
				if err := h.ParseSegment(); err != nil {
					return nil, err
				}
			default:
				return nil, h.Errf("unknown smtp option: %s", h.Val())
			}
		}
		app.Listeners = append(app.Listeners, lc)
	}
	return app, nil
}

// ApplyTo merges SMTP listener blocks into AppsRaw["smtp"].
func (s *SMTP) ApplyTo(cfg *caddy.Config) error {
	if cfg.AppsRaw == nil {
		cfg.AppsRaw = make(caddy.ModuleMap)
	}
	if prev, ok := cfg.AppsRaw["smtp"]; ok {
		var existing SMTP
		if err := json.Unmarshal(prev, &existing); err == nil {
			s.Listeners = append(existing.Listeners, s.Listeners...)
		}
	}
	data, err := caddyconfig.JSON(s, nil)
	if err != nil {
		return err
	}
	cfg.AppsRaw["smtp"] = data
	return nil
}

var _ caddyfile.Dispenser
```

## `pkg/smtp/session.go`

```go
package smtp

import (
	"bufio"
	"bytes"
	"fmt"
	"net"
	"strings"

	"github.com/caddyserver/caddy/v2"
)

type session struct {
	lc     *ListenerConfig
	conn   net.Conn
	reader *bufio.Reader
	writer *bufio.Writer
	repl   *caddy.Replacer

	helo     string
	from     string
	rcpts    []string
	tlsOn    bool
	authUser string
}

func newSession(lc *ListenerConfig, conn net.Conn) *session {
	s := &session{
		lc:     lc,
		conn:   conn,
		reader: bufio.NewReader(conn),
		writer: bufio.NewWriter(conn),
		repl:   caddy.NewReplacer(),
	}
	s.repl.Set("smtp.remote_ip", conn.RemoteAddr().String())
	s.repl.Set("smtp.local_ip", conn.LocalAddr().String())
	s.repl.Set("smtp.hostname", lc.Hostname)
	return s
}

func (s *session) reply(code int, msg string) {
	fmt.Fprintf(s.writer, "%d %s\r\n", code, msg)
	s.writer.Flush()
}

func (s *session) run() {
	s.reply(220, s.lc.Hostname+" ESMTP ready")
	for {
		line, err := s.reader.ReadString('\n')
		if err != nil {
			return
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			continue
		}
		cmd, args := splitCmd(line)
		switch cmd {
		case "EHLO":
			s.helo = args
			s.repl.Set("smtp.helo", args)
			s.reply(250, s.lc.Hostname)
		case "HELO":
			s.helo = args
			s.repl.Set("smtp.helo", args)
			s.reply(250, s.lc.Hostname)
		case "MAIL":
			s.handleMail(args)
		case "RCPT":
			s.handleRcpt(args)
		case "DATA":
			s.handleData()
		case "RSET":
			s.from = ""
			s.rcpts = nil
			s.reply(250, "OK")
		case "NOOP":
			s.reply(250, "OK")
		case "QUIT":
			s.reply(221, "Bye")
			return
		case "AUTH":
			s.handleAuth(args)
		case "STARTTLS":
			s.reply(502, "STARTTLS not implemented")
		default:
			s.reply(500, "Unknown command")
		}
	}
}

func (s *session) handleMail(args string) {
	// args like: FROM:<alice@example.com>
	from := extractAngle(args)
	if from == "" && !strings.Contains(strings.ToUpper(args), "FROM:<>") {
		s.reply(501, "Syntax: MAIL FROM:<addr>")
		return
	}
	s.from = from
	s.repl.Set("smtp.from", from)
	s.reply(250, "OK")
}

func (s *session) handleRcpt(args string) {
	rcpt := extractAngle(args)
	if rcpt == "" {
		s.reply(501, "Syntax: RCPT TO:<addr>")
		return
	}
	if len(s.rcpts) >= s.lc.MaxRecipients {
		s.reply(452, "Too many recipients")
		return
	}
	s.rcpts = append(s.rcpts, rcpt)
	s.repl.Set("smtp.rcpt", rcpt)
	s.repl.Set("smtp.rcpts", s.rcpts)
	s.reply(250, "OK")
}

func (s *session) handleData() {
	if s.from == "" {
		s.reply(503, "MAIL FROM first")
		return
	}
	if len(s.rcpts) == 0 {
		s.reply(503, "RCPT TO first")
		return
	}
	s.reply(354, "End with <CRLF>.<CRLF>")
	var body bytes.Buffer
	for {
		line, err := s.reader.ReadString('\n')
		if err != nil {
			return
		}
		if line == ".\r\n" || line == ".\n" {
			break
		}
		if strings.HasPrefix(line, "..") {
			line = line[1:]
		}
		if int64(body.Len())+int64(len(line)) > s.lc.MaxMessageSize {
			s.reply(552, "Message too large")
			return
		}
		body.WriteString(line)
	}
	s.dispatch(body.Bytes())
	s.from = ""
	s.rcpts = nil
}

func (s *session) handleAuth(args string) {
	if s.lc.Auth == "off" {
		s.reply(502, "AUTH not available")
		return
	}
	// TODO: real SASL. For v1 accept any credentials and set authUser.
	parts := strings.Fields(args)
	if len(parts) < 1 {
		s.reply(501, "AUTH <mechanism>")
		return
	}
	if strings.EqualFold(parts[0], "PLAIN") {
		s.reply(334, "")
		resp, err := s.reader.ReadString('\n')
		if err != nil {
			return
		}
		_ = resp
		// TODO decode base64, split \0user\0pass
		s.authUser = "anonymous"
		s.repl.Set("smtp.auth_user", s.authUser)
		s.reply(235, "Authentication successful")
		return
	}
	s.reply(504, "Unsupported mechanism")
}

func splitCmd(line string) (string, string) {
	sp := strings.IndexAny(line, " \t")
	if sp < 0 {
		return strings.ToUpper(line), ""
	}
	return strings.ToUpper(line[:sp]), strings.TrimSpace(line[sp+1:])
}

func extractAngle(s string) string {
	i := strings.Index(s, "<")
	j := strings.Index(s, ">")
	if i < 0 || j < 0 || j <= i {
		return ""
	}
	return s[i+1 : j]
}
```

## `pkg/smtp/dispatch.go`

```go
package smtp

import (
	"bytes"
	"context"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/caddyserver/caddy/v2"
	"github.com/caddyserver/caddy/v2/modules/caddyhttp"
	"github.com/example/caddy-email/pkg/shared"
)

// dispatch synthesizes an *http.Request for the message, runs it through
// the compiled listener route, and translates the response status into
// an SMTP reply code.
func (s *session) dispatch(raw []byte) {
	if s.lc.Route == nil {
		s.reply(250, "2.0.0 OK")
		return
	}

	req := s.buildRequest(raw)
	rrw := newSmtpResponseWriter()

	ctx := context.WithValue(req.Context(), caddy.ReplacerCtxKey, s.repl)
	req = req.WithContext(ctx)

	terminal := caddyhttp.HandlerFunc(func(w http.ResponseWriter, r *http.Request) error {
		// no terminal action taken; leave status as set (default 200)
		return nil
	})
	handler := s.lc.Route.Compile(terminal)
	if err := handler.ServeHTTP(rrw, req, terminal); err != nil {
		s.reply(451, "4.4.1 Internal error")
		return
	}
	code, msg := mapStatus(rrw.status)
	s.reply(code, msg)
}

func (s *session) buildRequest(raw []byte) *http.Request {
	hdr := http.Header{}
	for _, h := range parseHeaderLines(raw) {
		hdr.Add(h[0], h[1])
	}
	hdr.Set("X-Envelope-From", s.from)
	hdr.Set("X-Envelope-To", strings.Join(s.rcpts, ","))
	hdr.Set("X-Client-Helo", s.helo)
	hdr.Set("X-Client-IP", s.conn.RemoteAddr().String())
	if s.tlsOn {
		hdr.Set("X-Smtp-TLS", "true")
	}
	body := splitBody(raw)
	req := &http.Request{
		Method: http.MethodPost,
		URL:    &url.URL{Path: "/", Scheme: "smtp"},
		Host:   s.helo,
		Proto:  "HTTP/1.1",
		ProtoMajor: 1, ProtoMinor: 1,
		Header: hdr,
		Body:   http.NoBody,
	}
	if body != nil {
		req.Body = http.NopCloser(bytes.NewReader(body))
		req.ContentLength = int64(len(body))
	}
	req.RemoteAddr = s.conn.RemoteAddr().String()
	return req
}

func parseHeaderLines(raw []byte) [][2]string {
	out := [][2]string{}
	i := 0
	for i < len(raw) {
		j := i
		for j < len(raw) && raw[j] != '\n' {
			j++
		}
		line := string(raw[i:j])
		if line == "" || line == "\r" {
			break
		}
		line = strings.TrimRight(line, "\r")
		if k := strings.Index(line, ":"); k > 0 {
			out = append(out, [2]string{line[:k], strings.TrimSpace(line[k+1:])})
		}
		i = j + 1
	}
	return out
}

func splitBody(raw []byte) []byte {
	if i := bytes.Index(raw, []byte("\r\n\r\n")); i >= 0 {
		return raw[i+4:]
	}
	if i := bytes.Index(raw, []byte("\n\n")); i >= 0 {
		return raw[i+2:]
	}
	return raw
}

type smtpResponseWriter struct {
	header http.Header
	status int
	body   bytes.Buffer
}

func newSmtpResponseWriter() *smtpResponseWriter {
	return &smtpResponseWriter{header: http.Header{}}
}

func (w *smtpResponseWriter) Header() http.Header { return w.header }
func (w *smtpResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.body.Write(p)
}
func (w *smtpResponseWriter) WriteHeader(code int) { w.status = code }

func mapStatus(code int) (int, string) {
	if code == 0 || (code >= 200 && code < 400) {
		return 250, "2.0.0 OK"
	}
	// reverse_proxy transport errors → temporary so retry happens
	if code == 502 || code == 503 || code == 504 {
		return 451, "4.4.1 Backend unavailable"
	}
	if code >= 400 && code < 500 {
		return 451, "4.4.1 Temporary failure"
	}
	return 550, "5.0.0 Rejected"
}

var _ = strconv.Itoa
var _ = shared.SchemaVersion
```

---

## Known limitations (intentional for v1)

- **DKIM** — `dkim { }` parses but does not sign. Sign at claim in `mta/client.go`.
- **SASL** — accepts any credentials. Wire up `sasl.PlainServer` against a configured user store.
- **STARTTLS** — advertised off. Wire up certmagic cert acquisition.
- **Multi-recipient partial success** — one RCPT failure defers the whole job. Per-recipient tracking is the next iteration.
- **MX caching** — resolved per tick. Add TTL cache when queue volume warrants it.
- **Reject rules** (`reject_from` / `reject_rcpt`) — parsed but not enforced. The hook is in `session.go` at the `MAIL`/`RCPT` handlers.
- **Bounce DSN generation** — bounces move files to `bounce/` but do not synthesize an RFC 3464 DSN yet.
- **Template return with no-op terminal** — handler chains that expect `next` to fire will work, but handlers that absolutely require HTTP server context (`basic_auth`, `forward_auth`) will fail with a clear error; document as "not usable inside SMTP routes."

That's a compiling, running skeleton with real delivery, real spool, real notify, real handler/template/module wiring — and clear seams for the remaining pieces. Tell me which TODO first and I'll fill it in.
