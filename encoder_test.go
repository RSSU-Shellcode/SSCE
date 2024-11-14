//go:build windows

package ssce

import (
	"os"
	"runtime"
	"syscall"
	"testing"
	"unsafe"

	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/windows"
)

var encoder *Encoder

func TestMain(m *testing.M) {
	var err error
	encoder, err = NewEncoder()
	if err != nil {
		panic(err)
	}

	code := m.Run()

	err = encoder.Close()
	if err != nil {
		panic(err)
	}

	os.Exit(code)
}

func TestEncoderN(t *testing.T) {
	for i := 0; i < 20; i++ {
		TestEncoder(t)
	}
}

func TestEncoder(t *testing.T) {
	t.Run("x64", func(t *testing.T) {
		asm := ".code64\n"
		asm += "mov qword ptr [rcx], 0x64\n"
		asm += "mov rax, 0x64\n"
		asm += "ret\n"
		shellcode, err := encoder.engine64.Assemble(asm, 0)
		require.NoError(t, err)

		shellcode, err = encoder.Encode(shellcode, 64, nil)
		require.NoError(t, err)
		spew.Dump(shellcode)

		if runtime.GOARCH != "amd64" {
			return
		}
		addr := loadShellcode(t, shellcode)
		var val int
		ret, _, _ := syscall.SyscallN(addr, (uintptr)(unsafe.Pointer(&val)))
		require.Equal(t, 0x64, val)
		require.Equal(t, 0x64, int(ret))
	})

	t.Run("x86", func(t *testing.T) {
		asm := ".code32\n"
		asm += "mov eax, 0x86\n"
		asm += "ret\n"
		shellcode, err := encoder.engine64.Assemble(asm, 0)
		require.NoError(t, err)

		shellcode, err = encoder.Encode(shellcode, 32, nil)
		require.NoError(t, err)
		spew.Dump(shellcode)

		if runtime.GOARCH != "386" {
			return
		}
		addr := loadShellcode(t, shellcode)
		var val int
		ret, _, _ := syscall.SyscallN(addr, (uintptr)(unsafe.Pointer(&val)))
		require.Equal(t, 0x86, int(ret))
	})
}

func loadShellcode(t *testing.T, sc []byte) uintptr {
	size := uintptr(len(sc))
	mType := uint32(windows.MEM_COMMIT | windows.MEM_RESERVE)
	mProtect := uint32(windows.PAGE_EXECUTE_READWRITE)
	scAddr, err := windows.VirtualAlloc(0, size, mType, mProtect)
	require.NoError(t, err)
	dst := unsafe.Slice((*byte)(unsafe.Pointer(scAddr)), size)
	copy(dst, sc)
	return scAddr
}
