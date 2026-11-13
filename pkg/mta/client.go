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
