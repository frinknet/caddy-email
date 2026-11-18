//go:build !unix

package mta

import "io"

// lockSpool is a no-op on platforms without flock. The spool is still
// single-writer in practice because only one process is expected to own it.
func lockSpool(string) (io.Closer, error) { return nil, nil }
