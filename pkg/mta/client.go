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
	"strings"
	"time"

	"github.com/frinknet/caddy-email/pkg/shared"
	"go.uber.org/zap"
)

// deliverOne attempts delivery of one job to one MX host. On success the
// queue files are unlinked and a "delivered" event is POSTed. On failure
// the job is deferred (4xx) or bounced (5xx or retry exhausted).
//
// Per-recipient tracking: if some RCPTs fail while others succeed, the
// successful ones are delivered and new jobs are created for the failed
// recipients.
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

	dfPath := filepath.Join(m.SpoolDir, shared.StateActive, "df"+j.ID)
	body, err := os.ReadFile(dfPath)
	if err != nil {
		m.failPermanent(j, "read df: "+err.Error())
		return
	}

	// DKIM signing — sign body into a transient buffer, do not rewrite df.
	if m.DKIM != nil && m.DKIM.parsedKey != nil {
		fromDomain := ""
		if at := strings.LastIndex(j.From, "@"); at >= 0 {
			fromDomain = strings.ToLower(j.From[at+1:])
		}
		if m.DKIM.Domain != "" && fromDomain != "" && !strings.EqualFold(m.DKIM.Domain, fromDomain) {
			m.log.Warn("mta: dkim domain mismatch",
				zap.String("dkim_domain", m.DKIM.Domain),
				zap.String("sender_domain", fromDomain),
				zap.String("id", j.ID),
			)
		}
		signed, err := dkimSign(body, m.DKIM, fromDomain)
		if err != nil {
			m.log.Warn("mta: dkim sign", zap.String("id", j.ID), zap.Error(err))
		} else {
			body = signed
		}
	}

	if err := c.Mail(j.From); err != nil {
		m.failTemporary(j, "MAIL FROM: "+err.Error())
		return
	}

	// Track per-recipient results
	var good, bad []string
	for _, rcpt := range j.To {
		if err := c.Rcpt(rcpt); err != nil {
			bad = append(bad, rcpt)
			continue
		}
		good = append(good, rcpt)
	}

	if len(good) == 0 {
		// All recipients failed — defer the whole job
		m.failTemporary(j, fmt.Sprintf("all RCPT failed: %v", bad))
		return
	}

	w, err := c.Data()
	if err != nil {
		// Could not start data — defer everything
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

	// Unlink the original job (all recipients handled or re-enqueued)
	shared.Unlink(m.SpoolDir, j.ID)

	// Notify delivery for the successful recipients
	m.notify(shared.DeliveryEvent{
		QueueID:  j.ID,
		Event:    "delivered",
		Rcpt:     good,
		Attempts: j.Attempts + 1,
	})

	// Re-enqueue failed recipients as a new job
	if len(bad) > 0 {
		m.reEnqueue(j, body, bad)
	}
}

// reEnqueue creates a new deferred job for the given recipients using the
// same message body and sender. The new job inherits the attempt count so it
// won't start from zero.
func (m *MTA) reEnqueue(j *shared.Job, body []byte, rcpts []string) {
	env := &shared.Envelope{
		From: j.From,
		To:   rcpts,
	}
	newID, err := shared.Enqueue(m.SpoolDir, env, body)
	if err != nil {
		m.log.Error("mta: re-enqueue failed recipients",
			zap.String("orig_id", j.ID),
			zap.Strings("rcpts", rcpts),
			zap.Error(err),
		)
		return
	}
	// Move directly to deferred with same attempt count
	next := time.Now().Add(5 * time.Minute)
	if err := shared.Claim(m.SpoolDir, newID); err != nil {
		m.log.Error("mta: claim re-enqueued job",
			zap.String("id", newID),
			zap.Error(err),
		)
		return
	}
	if err := shared.Defer(m.SpoolDir, newID, next, j.Attempts+1, "partial delivery"); err != nil {
		m.log.Error("mta: defer re-enqueued job",
			zap.String("id", newID),
			zap.Error(err),
		)
	}
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
	nextAt := next
	m.notify(shared.DeliveryEvent{
		QueueID:  j.ID,
		Event:    "deferred",
		Rcpt:     j.To,
		Attempts: attempts,
		Message:  msg,
		NextAt:   &nextAt,
	})
}

func (m *MTA) failPermanent(j *shared.Job, msg string) {
	// Generate RFC 3464 DSN before moving to bounce
	dsnBody := m.buildDSN(j, msg)
	bnc := filepath.Join(m.SpoolDir, shared.StateBounce)
	os.MkdirAll(bnc, 0700)
	dsnPath := filepath.Join(bnc, "dsn"+j.ID)
	os.WriteFile(dsnPath, dsnBody, 0600)

	shared.Bounce(m.SpoolDir, j.ID)
	m.notify(shared.DeliveryEvent{
		QueueID:  j.ID,
		Event:    "bounced",
		Rcpt:     j.To,
		Attempts: j.Attempts + 1,
		Message:  msg,
	})
}

// buildDSN generates an RFC 3464-style delivery status notification.
func (m *MTA) buildDSN(j *shared.Job, msg string) []byte {
	var b strings.Builder
	b.WriteString("From: MAILER-DAEMON@" + m.Hostname + "\r\n")
	b.WriteString("To: " + j.From + "\r\n")
	b.WriteString("Subject: Mail delivery failed\r\n")
	b.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: multipart/report; report-type=delivery-status; boundary=\"dsn-boundary\"\r\n")
	b.WriteString("\r\n")
	b.WriteString("--dsn-boundary\r\n")
	b.WriteString("Content-Type: text/plain; charset=utf-8\r\n")
	b.WriteString("\r\n")
	b.WriteString("This message was created automatically by the mail system.\r\n")
	b.WriteString("Your message could not be delivered to one or more recipients.\r\n")
	b.WriteString("\r\n")
	b.WriteString(msg + "\r\n")
	b.WriteString("\r\n")
	b.WriteString("--dsn-boundary\r\n")
	b.WriteString("Content-Type: message/delivery-status\r\n")
	b.WriteString("\r\n")
	b.WriteString("Reporting-MTA: dns; " + m.Hostname + "\r\n")
	for _, rcpt := range j.To {
		b.WriteString("Final-Recipient: rfc822; " + rcpt + "\r\n")
		b.WriteString("Action: failed\r\n")
		b.WriteString("Status: 5.0.0\r\n")
		b.WriteString("Diagnostic-Code: smtp; " + msg + "\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString("--dsn-boundary--\r\n")
	return []byte(b.String())
}
