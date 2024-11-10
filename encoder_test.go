//go:build windows

package ssce

import (
	"runtime"
	"syscall"
	"testing"
	"unsafe"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

func TestEncoder(t *testing.T) {
	t.Run("x64", func(t *testing.T) {
		if runtime.GOARCH != "amd64" {
			return
		}

		encoder, err := NewEncoder(64)
		require.NoError(t, err)

		// xor eax, eax
		// add rax, 0x64
		// ret
		shellcode := []byte{
			0x31, 0xC0,
			0x48, 0x83, 0xC0, 0x64,
			0xC3,
		}
		shellcode, err = encoder.Encode(shellcode)
		require.NoError(t, err)

		err = encoder.Close()
		require.NoError(t, err)

		addr := loadShellcode(t, shellcode)
		ret, _, _ := syscall.SyscallN(addr)
		require.Equal(t, 0x64, int(ret))
	})

	t.Run("x86", func(t *testing.T) {
		if runtime.GOARCH != "386" {
			return
		}

		encoder, err := NewEncoder(32)
		require.NoError(t, err)

		// xor eax, eax
		// add eax, 0x86
		// ret
		shellcode := []byte{
			0x31, 0xC0,
			0x05, 0x86, 0x00, 0x00, 0x00,
			0xC3,
		}
		shellcode, err = encoder.Encode(shellcode)
		require.NoError(t, err)

		err = encoder.Close()
		require.NoError(t, err)

		addr := loadShellcode(t, shellcode)
		ret, _, _ := syscall.SyscallN(addr)
		require.Equal(t, 0x86, int(ret))
	})
}

func loadShellcode(t *testing.T, sc []byte) uintptr {
	spew.Dump(sc)
	size := uintptr(len(sc))
	mType := uint32(windows.MEM_COMMIT | windows.MEM_RESERVE)
	mProtect := uint32(windows.PAGE_EXECUTE_READWRITE)
	scAddr, err := windows.VirtualAlloc(0, size, mType, mProtect)
	require.NoError(t, err)
	dst := unsafe.Slice((*byte)(unsafe.Pointer(scAddr)), size)
	copy(dst, sc)
	return scAddr
}
