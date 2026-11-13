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
