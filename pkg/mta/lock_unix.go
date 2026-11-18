//go:build unix

package mta

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"syscall"
)

// spoolLockFileName lives inside the spool directory. flock is advisory and
// released automatically when the process exits, so a crash never leaves a
// stale lock behind.
const spoolLockFileName = ".caddy-email.lock"

type spoolLock struct{ f *os.File }

func (l *spoolLock) Close() error {
	syscall.Flock(int(l.f.Fd()), syscall.LOCK_UN)
	return l.f.Close()
}

// lockSpool takes an exclusive, non-blocking lock on the spool directory so
// that only one process delivers from it at a time.
func lockSpool(dir string) (io.Closer, error) {
	path := filepath.Join(dir, spoolLockFileName)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, fmt.Errorf("open spool lock %s: %w", path, err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB); err != nil {
		f.Close()
		return nil, fmt.Errorf("spool %s is locked by another instance: %w", dir, err)
	}
	return &spoolLock{f: f}, nil
}
