//go:build !windows

package ssce

import (
	"syscall"
	"testing"
)

func loadShellcode(t *testing.T, sc []byte) uintptr {
	return 0
}

// for cross-compile
//
//go:uintptrescapes
func syscallN(trap uintptr, args ...uintptr) (r1, r2 uintptr, err syscall.Errno) {
	return 0, 0, 0
}
