package mta

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"

	"github.com/frinknet/caddy-email/pkg/shared"
	"go.uber.org/zap"
)

// notify enqueues a delivery event for asynchronous webhook delivery.
// It never blocks the caller: if the buffer is full, the event is dropped
// with a warning. This keeps delivery goroutines from being throttled by
// a slow or unreachable webhook endpoint — the whole point of the "fire
// and forget" contract.
//
// When NotifyURL is empty, the event is logged and nothing else happens.
// That log line is the only observability surface the queue has, so it
// fires for every event (delivered, deferred, bounced).
func (m *MTA) notify(ev shared.DeliveryEvent) {
	if m.NotifyURL == "" {
		m.log.Info("mta: event",
			zap.String("queue_id", ev.QueueID),
			zap.String("event", ev.Event),
		)
		return
	}
	select {
	case m.notifyCh <- ev:
	default:
		m.log.Warn("mta: notify buffer full, dropping event",
			zap.String("id", ev.QueueID),
			zap.String("event", ev.Event),
		)
	}
}

// notifyWorker drains the buffer and POSTs events. Several workers run
// concurrently (see Start), so one slow endpoint only ties up one worker.
func (m *MTA) notifyWorker() {
	defer m.wg.Done()
	for {
		select {
		case <-m.stopCh:
			return
		case ev := <-m.notifyCh:
			m.sendNotify(ev)
		}
	}
}

// sendNotify performs the synchronous webhook POST. Delivery state is
// already committed to the spool before this runs, so errors are logged
// and forgotten — no retry, no replay, no ordering guarantee.
func (m *MTA) sendNotify(ev shared.DeliveryEvent) {
	body, err := json.Marshal(ev)
	if err != nil {
		m.log.Warn("mta: notify marshal", zap.String("id", ev.QueueID), zap.Error(err))
		return
	}
	req, err := http.NewRequest(http.MethodPost, m.NotifyURL, bytes.NewReader(body))
	if err != nil {
		m.log.Warn("mta: notify request", zap.String("id", ev.QueueID), zap.Error(err))
		return
	}
	req.Header.Set("Content-Type", "application/json")
	if m.NotifySecret != "" {
		req.Header.Set("MTA-Signature", shared.SignHMAC(m.NotifySecret, body))
	}
	resp, err := m.notifyClient.Do(req)
	if err != nil {
		m.log.Warn("mta: notify", zap.String("id", ev.QueueID), zap.Error(err))
		return
	}
	// Cap the drain so a misbehaving endpoint can't force us to read
	// an unbounded response body.
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4096))
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		m.log.Warn("mta: notify non-2xx",
			zap.Int("status", resp.StatusCode),
			zap.String("id", ev.QueueID),
		)
	}
}
