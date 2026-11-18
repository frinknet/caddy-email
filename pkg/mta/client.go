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

// metaDSN marks a job as a delivery status notification so that a failure to
// deliver the notification itself never generates another one.
const metaDSN = "dsn"

// deliverOne attempts delivery of one job, trying each MX host in preference
// order until one completes a connection and greeting. On success the queue
// files are unlinked and a "delivered" event is POSTed. On failure the job is
// deferred (4xx) or bounced (5xx or retry exhausted).
//
// Per-recipient tracking: if some RCPTs fail while others succeed, the
// successful ones are delivered and new jobs are created for the failed
// recipients.
func (m *MTA) deliverOne(hosts []string, j *shared.Job) {
	if len(hosts) == 0 {
		m.failPermanent(j, "no MX hosts for recipient domain")
		return
	}
	dfPath := filepath.Join(m.SpoolDir, shared.StateActive, "df"+j.ID)
	raw, err := os.ReadFile(dfPath)
	if err != nil {
		m.failPermanent(j, "read df: "+err.Error())
		return
	}

	// DKIM signs into a transient copy; the spooled df stays raw so a retry
	// is re-signed from scratch instead of accumulating nested signatures.
	body := raw
	if m.DKIM != nil && m.DKIM.parsedKey != nil {
		fromDomain := ""
		if at := strings.LastIndex(j.From, "@"); at >= 0 {
			fromDomain = strings.ToLower(j.From[at+1:])
		}
		if m.DKIM.Domain != "" && fromDomain != "" && !strings.EqualFold(m.DKIM.Domain, fromDomain) {
			m.logger().Warn("mta: dkim domain mismatch",
				zap.String("dkim_domain", m.DKIM.Domain),
				zap.String("sender_domain", fromDomain),
				zap.String("id", j.ID),
			)
		}
		signed, err := dkimSign(raw, m.DKIM, fromDomain)
		if err != nil {
			m.logger().Warn("mta: dkim sign", zap.String("id", j.ID), zap.Error(err))
		} else {
			body = signed
		}
	}

	// Try each MX host in preference order. Only when every host fails to
	// connect (or fails the greeting / TLS requirement) is the job deferred;
	// once connected, failures are per-message and retried on the next pass.
	var (
		c       *smtp.Client
		conn    net.Conn
		lastErr error
	)
	for _, host := range hosts {
		c, conn, lastErr = m.connectHost(host)
		if lastErr == nil {
			break
		}
		m.logger().Warn("mta: mx attempt failed",
			zap.String("id", j.ID),
			zap.String("mx", host),
			zap.Error(lastErr),
		)
	}
	if c == nil {
		m.failTemporary(j, fmt.Sprintf("all MX hosts failed: %v", lastErr))
		return
	}
	defer conn.Close()
	defer c.Close()

	good, bad, err := m.deliverSession(conn, c, j, body)
	if err != nil {
		m.failTemporary(j, err.Error())
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

	// Re-enqueue failed recipients as a new job, using the raw (unsigned) body.
	if len(bad) > 0 {
		m.reEnqueue(j, raw, bad)
	}
}

// connectHost dials one MX host and prepares an SMTP client, enforcing
// require_tls when configured. A non-nil error means the host is unusable for
// this attempt and the caller should try the next one.
func (m *MTA) connectHost(host string) (*smtp.Client, net.Conn, error) {
	dialer := &net.Dialer{Timeout: time.Duration(m.ConnectTimeout)}
	conn, err := dialer.Dial("tcp", net.JoinHostPort(host, m.dialPort()))
	if err != nil {
		return nil, nil, fmt.Errorf("connect %s: %w", host, err)
	}
	if d := time.Duration(m.CommandTimeout); d > 0 {
		conn.SetDeadline(time.Now().Add(d))
	}

	c, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return nil, nil, fmt.Errorf("greeting %s: %w", host, err)
	}

	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: host, MinVersion: tls.VersionTLS12}); err != nil {
			c.Close()
			conn.Close()
			return nil, nil, fmt.Errorf("starttls %s: %w", host, err)
		}
	} else if m.RequireTLS {
		c.Close()
		conn.Close()
		return nil, nil, fmt.Errorf("require_tls: %s does not offer STARTTLS", host)
	}
	return c, conn, nil
}

// deliverSession runs MAIL/RCPT/DATA over an established connection. It returns
// the accepted and rejected recipients; a non-nil error means nothing was
// delivered and the job should be deferred.
func (m *MTA) deliverSession(conn net.Conn, c *smtp.Client, j *shared.Job, body []byte) (good, bad []string, err error) {
	if err := c.Mail(j.From); err != nil {
		return nil, nil, fmt.Errorf("MAIL FROM: %w", err)
	}

	for _, rcpt := range j.To {
		if err := c.Rcpt(rcpt); err != nil {
			bad = append(bad, rcpt)
			continue
		}
		good = append(good, rcpt)
	}
	if len(good) == 0 {
		return nil, bad, fmt.Errorf("all RCPT failed: %v", bad)
	}

	w, err := c.Data()
	if err != nil {
		return nil, nil, fmt.Errorf("DATA: %w", err)
	}
	// Bound the body transfer by data_timeout rather than the much longer
	// command_timeout, then restore the command deadline for the final reply.
	if d := time.Duration(m.DataTimeout); d > 0 {
		conn.SetDeadline(time.Now().Add(d))
	}
	if _, err := w.Write(body); err != nil {
		return nil, nil, fmt.Errorf("write body: %w", err)
	}
	if err := w.Close(); err != nil {
		return nil, nil, fmt.Errorf("close data: %w", err)
	}
	if d := time.Duration(m.CommandTimeout); d > 0 {
		conn.SetDeadline(time.Now().Add(d))
	}
	return good, bad, nil
}

// reEnqueue creates a new deferred job for the given recipients using the
// same message body and sender. The new job inherits the attempt count so it
// won't start from zero; once retries are exhausted the recipients are
// bounced instead.
func (m *MTA) reEnqueue(j *shared.Job, body []byte, rcpts []string) {
	if j.Attempts+1 > m.MaxRetries {
		m.failRecipients(j, rcpts, fmt.Sprintf("retries exhausted for %v", rcpts))
		return
	}
	env := &shared.Envelope{
		From: j.From,
		To:   rcpts,
		Meta: j.Meta,
	}
	newID, err := shared.Enqueue(m.SpoolDir, env, body)
	if err != nil {
		m.logger().Error("mta: re-enqueue failed recipients",
			zap.String("orig_id", j.ID),
			zap.Strings("rcpts", rcpts),
			zap.Error(err),
		)
		return
	}
	// Move directly to deferred with same attempt count
	next := time.Now().Add(5 * time.Minute)
	if err := shared.Claim(m.SpoolDir, newID); err != nil {
		m.logger().Error("mta: claim re-enqueued job",
			zap.String("id", newID),
			zap.Error(err),
		)
		return
	}
	if err := shared.Defer(m.SpoolDir, newID, next, j.Attempts+1, "partial delivery"); err != nil {
		m.logger().Error("mta: defer re-enqueued job",
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
	// Exponential backoff, clamped so a large max_retries cannot overflow the
	// shift into a negative duration.
	shift := attempts - 1
	if shift > 20 {
		shift = 20
	}
	backoff := time.Duration(m.InitialBackoff) * (1 << uint(shift))
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
		m.logger().Error("mta: defer", zap.String("id", j.ID), zap.Error(err))
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

// failPermanent archives the message in bounce/ and, unless bouncing would
// create a loop, queues an RFC 3464 DSN back to the envelope sender.
func (m *MTA) failPermanent(j *shared.Job, msg string) {
	shared.Bounce(m.SpoolDir, j.ID)
	m.failRecipients(j, j.To, msg)
}

// failRecipients notifies a bounce for the given recipients and queues a DSN to
// the sender. Bounce loops are suppressed: a null sender, an existing DSN, or a
// MAILER-DAEMON sender never produces another notification.
func (m *MTA) failRecipients(j *shared.Job, rcpts []string, msg string) {
	m.notify(shared.DeliveryEvent{
		QueueID:  j.ID,
		Event:    "bounced",
		Rcpt:     rcpts,
		Attempts: j.Attempts + 1,
		Message:  msg,
	})

	if !m.canBounce(j) {
		return
	}
	dsn := m.buildDSNFor(j, rcpts, msg)
	env := &shared.Envelope{
		From: "MAILER-DAEMON@" + m.Hostname,
		To:   []string{j.From},
		Meta: map[string]string{metaDSN: "1"},
	}
	if _, err := shared.Enqueue(m.SpoolDir, env, dsn); err != nil {
		m.logger().Error("mta: queue bounce DSN",
			zap.String("id", j.ID),
			zap.String("rcpt", j.From),
			zap.Error(err),
		)
		return
	}
	m.logger().Info("mta: bounce DSN queued",
		zap.String("id", j.ID),
		zap.String("rcpt", j.From),
	)
}

// canBounce reports whether a failure notification may be sent to j's sender
// without risking a mail loop or an undeliverable notification.
func (m *MTA) canBounce(j *shared.Job) bool {
	if !shared.ValidAddress(j.From) {
		return false
	}
	if j.Meta[metaDSN] == "1" {
		return false
	}
	local := j.From
	if at := strings.LastIndex(j.From, "@"); at >= 0 {
		local = j.From[:at]
	}
	return !strings.EqualFold(local, "MAILER-DAEMON")
}

// buildDSN generates an RFC 3464-style delivery status notification for every
// recipient on the job.
func (m *MTA) buildDSN(j *shared.Job, msg string) []byte {
	return m.buildDSNFor(j, j.To, msg)
}

// buildDSNFor generates an RFC 3464-style delivery status notification for the
// given recipients.
func (m *MTA) buildDSNFor(j *shared.Job, rcpts []string, msg string) []byte {
	msg = shared.SanitizeHeaderValue(msg)
	var b strings.Builder
	b.WriteString("From: MAILER-DAEMON@" + m.Hostname + "\r\n")
	b.WriteString("To: " + shared.SanitizeHeaderValue(j.From) + "\r\n")
	b.WriteString("Subject: Mail delivery failed\r\n")
	b.WriteString("Date: " + time.Now().Format(time.RFC1123Z) + "\r\n")
	b.WriteString("Auto-Submitted: auto-replied\r\n")
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
	for _, rcpt := range rcpts {
		b.WriteString("\r\n")
		b.WriteString("Final-Recipient: rfc822; " + shared.SanitizeHeaderValue(rcpt) + "\r\n")
		b.WriteString("Action: failed\r\n")
		b.WriteString("Status: 5.0.0\r\n")
		b.WriteString("Diagnostic-Code: smtp; " + msg + "\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString("--dsn-boundary--\r\n")
	return []byte(b.String())
}
