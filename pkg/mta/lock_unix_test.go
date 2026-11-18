//go:build unix

package mta

import (
	"testing"

	"go.uber.org/zap"
)

func TestLockSpoolExclusive(t *testing.T) {
	dir := newSpool(t)

	l1, err := lockSpool(dir)
	if err != nil {
		t.Fatalf("first lockSpool: %v", err)
	}
	if _, err := lockSpool(dir); err == nil {
		l1.Close()
		t.Fatal("expected a second lockSpool to fail while the first is held")
	}
	if err := l1.Close(); err != nil {
		t.Fatalf("release lock: %v", err)
	}

	l2, err := lockSpool(dir)
	if err != nil {
		t.Fatalf("lockSpool after release: %v", err)
	}
	l2.Close()
}

func TestStartRejectsSecondInstance(t *testing.T) {
	dir := newSpool(t)

	m := &MTA{SpoolDir: dir, Hostname: "mail.test", log: zap.NewNop()}
	m.applyDefaults()
	if err := m.Start(); err != nil {
		t.Fatalf("first Start: %v", err)
	}

	m2 := &MTA{SpoolDir: dir, Hostname: "mail.test", log: zap.NewNop()}
	m2.applyDefaults()
	if err := m2.Start(); err == nil {
		t.Error("expected a second instance to refuse the locked spool")
	}

	if err := m.Stop(); err != nil {
		t.Fatalf("Stop: %v", err)
	}

	m3 := &MTA{SpoolDir: dir, Hostname: "mail.test", log: zap.NewNop()}
	m3.applyDefaults()
	if err := m3.Start(); err != nil {
		t.Fatalf("Start after the lock was released: %v", err)
	}
	m3.Stop()
}
