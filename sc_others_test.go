//go:build !windows

package ssce

import (
	"testing"
)

func loadShellcode(t *testing.T, sc []byte) uintptr {
	return 0
}
