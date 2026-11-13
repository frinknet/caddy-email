package mta

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/caddyserver/caddy/v2"
	"go.uber.org/zap"

	"github.com/example/caddy-email/pkg/shared"
)

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

	log          *zap.Logger
	stopCh       chan struct{}
	wg           sync.WaitGroup
	notifyClient *http.Client
	mxSem        map[string]chan struct{}
	mxSemMu      sync.Mutex
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

// Ensure context is used
var _ = context.Background
