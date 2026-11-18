package mta

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"github.com/frinknet/caddy-email/pkg/shared"
)

// notifyWorkers is the number of concurrent webhook POSTers. Four is
// enough to keep a normal event stream drained without a slow endpoint
// blocking anything else; each worker holds at most one in-flight POST.
const notifyWorkers = 4

// notifyBuffer is the maximum number of events queued for webhook
// delivery before new events are dropped. Sized to absorb a burst from
// a full concurrency batch.
const notifyBuffer = 1024

// spoolJanitorInterval is how often the janitor recomputes the spool size for
// quota accounting and prunes expired bounce archives.
const spoolJanitorInterval = 30 * time.Second

func init() {
	caddy.RegisterModule(new(MTA))
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
	MxCacheTTL       caddy.Duration `json:"mx_cache_ttl,omitempty"`
	RequireTLS       bool           `json:"require_tls,omitempty"`
	Relay            string         `json:"relay,omitempty"`
	MaxSpoolBytes    int64          `json:"max_spool_bytes,omitempty"`
	BounceRetention  caddy.Duration `json:"bounce_retention,omitempty"`
	ShutdownTimeout  caddy.Duration `json:"shutdown_timeout,omitempty"`
	DKIM             *DKIMConfig    `json:"dkim,omitempty"`

	log          *zap.Logger
	stopCh       chan struct{}
	stopOnce     sync.Once
	wg           sync.WaitGroup
	notifyClient *http.Client
	notifyCh     chan shared.DeliveryEvent
	mxSem        map[string]mxSemEntry
	mxSemMu      sync.Mutex
	globalSem    chan struct{}
	mxCache      map[string]mxCacheEntry
	mxCacheMu    sync.RWMutex

	// inFlight tracks job IDs currently being delivered, so the janitor's
	// crash recovery never requeues a live delivery.
	inFlightMu sync.Mutex
	inFlight   map[string]struct{}

	// smtpPort is the port dialed on MX hosts. It is 25 in production and
	// overridable only from tests.
	smtpPort   string
	spoolLock  io.Closer
	spoolBytes atomic.Int64
}

func (*MTA) CaddyModule() caddy.ModuleInfo {
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
	m.notifyCh = make(chan shared.DeliveryEvent, notifyBuffer)
	if m.NotifyURL != "" {
		m.notifyClient = &http.Client{Timeout: 10 * time.Second}
	}
	m.mxSem = make(map[string]mxSemEntry)
	m.mxCache = make(map[string]mxCacheEntry)

	if m.DKIM != nil && m.DKIM.PrivateKey != "" {
		key, err := parseDKIMKey(m.DKIM.PrivateKey)
		if err != nil {
			return fmt.Errorf("mta: dkim: %w", err)
		}
		m.DKIM.parsedKey = key
	}
	if err := registerMetrics(ctx.GetMetricsRegistry(), m.SpoolDir); err != nil {
		// Observability is not worth failing startup for: log and carry on.
		m.logger().Warn("mta: metrics registration failed", zap.Error(err))
	}
	return nil
}

// logger returns the configured logger, falling back to a no-op logger so the
// module stays usable when it was not Provisioned (as in tests).
func (m *MTA) logger() *zap.Logger {
	if m.log == nil {
		return zap.NewNop()
	}
	return m.log
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
	if m.MxCacheTTL == 0 {
		m.MxCacheTTL = caddy.Duration(5 * time.Minute)
	}
	if m.smtpPort == "" {
		m.smtpPort = "25"
	}
	if m.BounceRetention == 0 {
		m.BounceRetention = caddy.Duration(7 * 24 * time.Hour)
	}
	if m.ShutdownTimeout == 0 {
		m.ShutdownTimeout = caddy.Duration(30 * time.Second)
	}
}

func (m *MTA) Validate() error {
	if m.SettleDelay < 0 {
		return fmt.Errorf("mta: settle_delay must be >= 0")
	}
	if m.Concurrency < 1 {
		return fmt.Errorf("mta: concurrency must be > 0")
	}
	if m.PerMXConcurrency < 1 {
		return fmt.Errorf("mta: per_mx_concurrency must be > 0")
	}
	if m.MaxBatch < 1 {
		return fmt.Errorf("mta: max_batch must be > 0")
	}
	if m.MaxRetries < 0 {
		return fmt.Errorf("mta: max_retries must be >= 0")
	}
	if m.MaxSpoolBytes < 0 {
		return fmt.Errorf("mta: max_spool_bytes must be >= 0")
	}
	for _, d := range []struct {
		name string
		val  caddy.Duration
	}{
		{"tick_interval", m.TickInterval},
		{"connect_timeout", m.ConnectTimeout},
		{"data_timeout", m.DataTimeout},
		{"command_timeout", m.CommandTimeout},
		{"mx_cache_ttl", m.MxCacheTTL},
		{"shutdown_timeout", m.ShutdownTimeout},
		{"initial_backoff", m.InitialBackoff},
		{"max_backoff", m.MaxBackoff},
		{"bounce_retention", m.BounceRetention},
	} {
		if d.val < 0 {
			return fmt.Errorf("mta: %s must be >= 0", d.name)
		}
	}
	if m.InitialBackoff > 0 && m.MaxBackoff > 0 && m.InitialBackoff > m.MaxBackoff {
		return fmt.Errorf("mta: initial_backoff must not exceed max_backoff")
	}
	if m.Relay != "" {
		if host, _, _ := m.relaySpec(); host == "" {
			return fmt.Errorf("mta: invalid relay %q", m.Relay)
		}
	}
	if m.NotifyURL != "" {
		u, err := url.Parse(m.NotifyURL)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("mta: invalid notify_url %q", m.NotifyURL)
		}
		if m.NotifySecret == "" {
			m.logger().Warn("mta: notify_url set without notify_secret; events will be unsigned")
		}
	}
	if m.NotifyURL == "" && m.NotifySecret != "" {
		m.logger().Warn("mta: notify_secret set without notify_url; no events will be sent")
	}
	return nil
}

func (m *MTA) Start() error {
	// The spool is single-writer: two Caddy instances sharing a spool_dir
	// would race on the same queue files, so refuse to start if another
	// process holds the lock.
	lock, err := lockSpool(m.SpoolDir)
	if err != nil {
		return fmt.Errorf("mta: %w", err)
	}
	m.spoolLock = lock

	m.stopCh = make(chan struct{})
	m.globalSem = make(chan struct{}, m.Concurrency)
	// Guard against Start being reached without Provision (which normally
	// creates these); a nil map would panic on the first write.
	if m.mxCache == nil {
		m.mxCache = make(map[string]mxCacheEntry)
	}
	if m.mxSem == nil {
		m.mxSem = make(map[string]mxSemEntry)
	}
	if m.notifyCh == nil {
		m.notifyCh = make(chan shared.DeliveryEvent, notifyBuffer)
	}
	if size, err := shared.SpoolSize(m.SpoolDir); err == nil {
		m.spoolBytes.Store(size)
	}
	if m.inFlight == nil {
		m.inFlight = make(map[string]struct{})
	}
	// Heal any pair a crash split before recovering active jobs, so a stranded
	// df is reunited with its qf instead of being skipped.
	if n := shared.ReconcileSpool(m.SpoolDir); n > 0 {
		m.logger().Info("mta: reconciled spool", zap.Int("repairs", n))
	}
	recovered := m.recoverActive(2 * time.Duration(m.ConnectTimeout))
	if recovered > 0 {
		m.logger().Info("mta: recovered active messages", zap.Int("count", recovered))
	}

	if m.NotifyURL != "" {
		for i := 0; i < notifyWorkers; i++ {
			m.wg.Add(1)
			go m.notifyWorker()
		}
	}

	m.wg.Add(1)
	go m.loop()
	m.wg.Add(1)
	go m.janitor()
	return nil
}

func (m *MTA) Stop() error {
	if m.stopCh == nil {
		return nil
	}
	m.stopOnce.Do(func() { close(m.stopCh) })

	// Wait for in-flight deliveries, but not forever: a reload or shutdown
	// must not block for the whole command_timeout.
	done := make(chan struct{})
	go func() {
		m.wg.Wait()
		close(done)
	}()
	timeout := time.Duration(m.ShutdownTimeout)
	if timeout <= 0 {
		timeout = 30 * time.Second
	}
	select {
	case <-done:
	case <-time.After(timeout):
		m.logger().Warn("mta: shutdown timed out; abandoning in-flight deliveries",
			zap.Duration("timeout", timeout))
	}

	if m.spoolLock != nil {
		m.spoolLock.Close()
		m.spoolLock = nil
	}
	return nil
}

// recoverActive requeues stale active/ jobs, skipping any delivery that is
// still in flight in this process.
func (m *MTA) recoverActive(cutoff time.Duration) int {
	return shared.RecoverActive(m.SpoolDir, cutoff, m.isInFlight)
}

func (m *MTA) isInFlight(id string) bool {
	m.inFlightMu.Lock()
	defer m.inFlightMu.Unlock()
	_, ok := m.inFlight[id]
	return ok
}

func (m *MTA) markInFlight(id string) {
	m.inFlightMu.Lock()
	m.inFlight[id] = struct{}{}
	m.inFlightMu.Unlock()
}

func (m *MTA) clearInFlight(id string) {
	m.inFlightMu.Lock()
	delete(m.inFlight, id)
	m.inFlightMu.Unlock()
}

// janitor periodically recomputes the spool size for quota accounting and
// prunes expired bounce archives so they cannot grow without bound.
func (m *MTA) janitor() {
	defer m.wg.Done()
	ticker := time.NewTicker(spoolJanitorInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.stopCh:
			return
		case <-ticker.C:
			if size, err := shared.SpoolSize(m.SpoolDir); err == nil {
				m.spoolBytes.Store(size)
			}
			// Repair crash-split pairs and requeue stale active jobs on every
			// pass: a job claimed moments before a crash is initially too
			// recent to recover, so it must get a second chance later.
			if n := shared.ReconcileSpool(m.SpoolDir); n > 0 {
				m.logger().Info("mta: reconciled spool", zap.Int("repairs", n))
			}
			if n := m.recoverActive(2 * time.Duration(m.ConnectTimeout)); n > 0 {
				m.logger().Info("mta: recovered stale active messages", zap.Int("count", n))
			}
			if r := time.Duration(m.BounceRetention); r > 0 {
				cutoff := time.Now().Add(-r)
				if n := shared.PruneBounce(m.SpoolDir, cutoff); n > 0 {
					m.logger().Info("mta: pruned bounce archive", zap.Int("files", n))
				}
				if n := shared.PruneCorrupt(m.SpoolDir, cutoff); n > 0 {
					m.logger().Info("mta: pruned corrupt archive", zap.Int("files", n))
				}
			}
			m.pruneMaps(time.Now())
		}
	}
}

// Enqueue implements shared.Enqueuer; delegates to the package function after
// enforcing the spool quota.
func (m *MTA) Enqueue(_ context.Context, env *shared.Envelope, raw []byte) (string, error) {
	raw = shared.EnsureMessageID(raw, env.From, m.Hostname)
	if err := m.checkQuota(int64(len(raw))); err != nil {
		return "", err
	}
	id, err := shared.Enqueue(m.SpoolDir, env, raw)
	if err != nil {
		return "", err
	}
	m.spoolBytes.Add(int64(len(raw)))
	metricEnqueued.Inc()
	return id, nil
}

// checkQuota rejects a message that would push the spool past max_spool_bytes.
// The size is an approximation refreshed by the janitor and incremented on
// every accepted message.
func (m *MTA) checkQuota(incoming int64) error {
	if m.MaxSpoolBytes <= 0 {
		return nil
	}
	if m.spoolBytes.Load()+incoming > m.MaxSpoolBytes {
		return shared.ErrSpoolFull
	}
	return nil
}
