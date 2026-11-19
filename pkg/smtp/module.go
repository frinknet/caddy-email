package smtp

import (
	"crypto/tls"
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
	caddy.RegisterModule(new(SMTP))
}

type SMTP struct {
	Listeners []*ListenerConfig `json:"listeners,omitempty"`

	log      *zap.Logger
	lns      []net.Listener
	stopCh   chan struct{}
	stopOnce sync.Once
	wg       sync.WaitGroup
}

// ListenerConfig describes one receive-only SMTP listener.
//
// The listener's only job is transport + parse + handoff. It accepts
// unauthenticated SMTP from anyone who can reach the port, parses the
// message, synthesizes an *http.Request, and runs the route. All policy
// decisions belong to the route, which signals acceptance/rejection via
// HTTP status — mapStatus translates that back to an SMTP reply code.
type ListenerConfig struct {
	Port           int                 `json:"port,omitempty"`
	Hostname       string              `json:"hostname,omitempty"`
	MaxMessageSize int64               `json:"max_message_size,omitempty"`
	MaxRecipients  int                 `json:"max_recipients,omitempty"`
	MaxConnections int                 `json:"max_connections,omitempty"`
	MaxIPClients   int                 `json:"max_ip_clients,omitempty"`
	DeliverTimeout caddy.Duration      `json:"deliver_timeout,omitempty"`
	TLS            string              `json:"tls,omitempty"` // "starttls" | "off"
	TLSCertFile    string              `json:"tls_cert_file,omitempty"`
	TLSKeyFile     string              `json:"tls_key_file,omitempty"`
	Route          *caddyhttp.Subroute `json:"route,omitempty"`

	tlsCert *tls.Certificate
}

func (*SMTP) CaddyModule() caddy.ModuleInfo {
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
		if lc.MaxIPClients == 0 {
			lc.MaxIPClients = 50
		}
		if lc.DeliverTimeout == 0 {
			lc.DeliverTimeout = caddy.Duration(30 * time.Second)
		}
		if lc.TLS == "" {
			lc.TLS = "off"
		}
		if lc.TLS == "starttls" && lc.TLSCertFile != "" && lc.TLSKeyFile != "" {
			cert, err := tls.LoadX509KeyPair(lc.TLSCertFile, lc.TLSKeyFile)
			if err != nil {
				return fmt.Errorf("smtp :%d load tls cert: %w", lc.Port, err)
			}
			lc.tlsCert = &cert
		}
		if lc.Route != nil {
			if err := lc.Route.Provision(ctx); err != nil {
				return fmt.Errorf("smtp :%d route: %w", lc.Port, err)
			}
		}
	}
	if err := registerMetrics(ctx.GetMetricsRegistry()); err != nil {
		// Observability is not worth failing startup for: log and carry on.
		s.log.Warn("smtp: metrics registration failed", zap.Error(err))
	}
	return nil
}

func (s *SMTP) Validate() error {
	for _, lc := range s.Listeners {
		if lc.Port == 0 {
			return fmt.Errorf("smtp: listener port required")
		}
		if lc.MaxConnections < 0 {
			return fmt.Errorf("smtp :%d max_connections must be >= 0", lc.Port)
		}
		if lc.MaxIPClients < 0 {
			return fmt.Errorf("smtp :%d max_ip_clients must be >= 0", lc.Port)
		}
		if lc.MaxMessageSize < 0 {
			return fmt.Errorf("smtp :%d max_message_size must be >= 0", lc.Port)
		}
		if lc.MaxRecipients < 0 {
			return fmt.Errorf("smtp :%d max_recipients must be >= 0", lc.Port)
		}
		if lc.TLS != "" && lc.TLS != "starttls" && lc.TLS != "off" {
			return fmt.Errorf("smtp :%d invalid tls value %q (must be \"starttls\" or \"off\")", lc.Port, lc.TLS)
		}
		if lc.TLS == "starttls" && (lc.TLSCertFile == "" || lc.TLSKeyFile == "") {
			return fmt.Errorf("smtp :%d tls=starttls requires tls_cert_file and tls_key_file", lc.Port)
		}
	}
	return nil
}

func (s *SMTP) Start() error {
	s.stopOnce = sync.Once{}
	s.stopCh = make(chan struct{})
	s.lns = nil
	for _, lc := range s.Listeners {
		addr := fmt.Sprintf(":%d", lc.Port)
		ln, err := net.Listen("tcp", addr)
		if err != nil {
			// Release every listener already bound by this attempt so a
			// partial failure does not leave ports held.
			s.stopOnce.Do(func() { close(s.stopCh) })
			for _, bound := range s.lns {
				bound.Close()
			}
			s.wg.Wait()
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
	if s.stopCh == nil {
		return nil
	}
	s.stopOnce.Do(func() { close(s.stopCh) })
	for _, ln := range s.lns {
		ln.Close()
	}
	s.wg.Wait()
	return nil
}

func (s *SMTP) serve(lc *ListenerConfig, ln net.Listener) {
	defer s.wg.Done()
	sem := make(chan struct{}, lc.MaxConnections)
	perIP := newIPLimiter(lc.MaxIPClients)
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
		ip := remoteIP(conn.RemoteAddr())
		if perIP != nil && !perIP.acquire(ip) {
			metricIPRejections.Inc()
			s.log.Warn("smtp: per-IP connection limit reached",
				zap.String("ip", ip), zap.Int("max_ip_clients", lc.MaxIPClients))
			rejectTooManyConnections(lc, conn)
			continue
		}
		metricConnections.Inc()
		sem <- struct{}{}
		go func(c net.Conn, ip string) {
			defer func() { <-sem }()
			defer c.Close()
			if perIP != nil {
				defer perIP.release(ip)
			}
			newSession(lc, c).run()
		}(conn, ip)
	}
}
