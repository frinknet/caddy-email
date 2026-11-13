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
