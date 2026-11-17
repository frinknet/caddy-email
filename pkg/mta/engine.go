package mta

import (
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
	jobs, err := shared.ScanEligible(m.SpoolDir, time.Duration(m.SettleDelay), m.MaxBatch)
	if err != nil {
		m.log.Error("mta: scan", zap.Error(err))
		return
	}
	if len(jobs) == 0 {
		return
	}

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

	groups := m.groupByMX(claimed, m.log)
	var wg sync.WaitGroup
	for mx, batch := range groups {
		wg.Add(1)
		go func(host string, jobs []*shared.Job) {
			defer wg.Done()
			m.globalSem <- struct{}{}
			defer func() { <-m.globalSem }()
			m.withMXSem(host, func() {
				for _, j := range jobs {
					m.deliverOne(host, j)
				}
			})
		}(mx, batch)
	}
	wg.Wait()
}

func (m *MTA) withMXSem(mx string, fn func()) {
	m.mxSemMu.Lock()
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
