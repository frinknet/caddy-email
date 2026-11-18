package mta

import (
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/frinknet/caddy-email/pkg/shared"
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
	shared.SweepDeferred(m.SpoolDir, time.Now())

	jobs, err := shared.ScanEligible(m.SpoolDir, time.Duration(m.SettleDelay), m.MaxBatch)
	if err != nil {
		m.logger().Error("mta: scan", zap.Error(err))
		return
	}
	if len(jobs) == 0 {
		return
	}

	// Enforce one domain per job before grouping: a multi-domain job would
	// land in several MX groups and be delivered concurrently, duplicating
	// copies and racing on the spool files.
	jobs = m.splitMultiDomain(jobs)

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

	groups := m.groupByMX(claimed)
	var wg sync.WaitGroup
	for _, g := range groups {
		wg.Add(1)
		go func(g *mxGroup) {
			defer wg.Done()
			select {
			case m.globalSem <- struct{}{}:
			case <-m.stopCh:
				return
			}
			defer func() { <-m.globalSem }()
			m.withMXSem(g.key, func() {
				for _, j := range g.jobs {
					select {
					case <-m.stopCh:
						return
					default:
					}
					m.deliverOne(g.hosts, j)
				}
			})
		}(g)
	}
	wg.Wait()
}

// splitMultiDomain ensures every job targets recipients in a single domain.
// A multi-domain job would otherwise be placed in more than one MX group by
// groupByMX and delivered by concurrent goroutines, so each MX would only
// accept its own recipients and then re-enqueue the others, yielding
// duplicate copies and races on the spool files.
//
// The job's original ID keeps its first domain's recipients; every remaining
// domain becomes a new job sharing the message body and attempt state.
func (m *MTA) splitMultiDomain(jobs []*shared.Job) []*shared.Job {
	out := make([]*shared.Job, 0, len(jobs))
	for _, j := range jobs {
		byDomain := map[string][]string{}
		var order []string
		var malformed []string
		for _, rcpt := range j.To {
			dom := recipientDomain(rcpt)
			if dom == "" {
				malformed = append(malformed, rcpt)
				continue
			}
			if _, ok := byDomain[dom]; !ok {
				order = append(order, dom)
			}
			byDomain[dom] = append(byDomain[dom], rcpt)
		}
		if len(order) <= 1 {
			out = append(out, j)
			continue
		}

		dfPath := filepath.Join(m.SpoolDir, shared.StateIncoming, "df"+j.ID)
		raw, err := os.ReadFile(dfPath)
		if err != nil {
			m.logger().Error("mta: read df for split", zap.String("id", j.ID), zap.Error(err))
			continue
		}

		first := order[0]
		byDomain[first] = append(byDomain[first], malformed...)

		// Write the extra-domain clones before trimming the original. If the
		// process dies between the two, the original still lists every
		// recipient (at worst a duplicate) instead of losing the domains that
		// were already stripped from its qf.
		var clones []*shared.Job
		for _, dom := range order[1:] {
			id, err := shared.CloneJob(m.SpoolDir, j, byDomain[dom], raw)
			if err != nil {
				m.logger().Error("mta: split job",
					zap.String("orig_id", j.ID),
					zap.String("domain", dom),
					zap.Error(err),
				)
				continue
			}
			clone := *j
			clone.ID = id
			clone.To = byDomain[dom]
			clones = append(clones, &clone)
		}

		if err := shared.RewriteRecipients(m.SpoolDir, j.ID, byDomain[first]); err != nil {
			m.logger().Error("mta: rewrite recipients", zap.String("id", j.ID), zap.Error(err))
			continue
		}
		j.To = byDomain[first]
		out = append(out, j)
		out = append(out, clones...)
	}
	return out
}

func (m *MTA) withMXSem(mx string, fn func()) {
	m.mxSemMu.Lock()
	if m.mxSem == nil {
		m.mxSem = make(map[string]chan struct{})
	}
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
