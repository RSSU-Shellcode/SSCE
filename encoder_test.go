package ssce

import (
	"net/http"
	"net/http/pprof"
	"runtime"
	"syscall"
	"testing"
	"unsafe"

	"github.com/For-ACGN/go-keystone"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestEncoderN(t *testing.T) {
	asm := ".code64\n"
	asm += "mov qword ptr [rcx], 0x64\n"
	asm += "mov rax, 0x64\n"
	asm += "ret\n"
	engine, err := keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_64)
	require.NoError(t, err)
	shellcode, err := engine.Assemble(asm, 0)
	require.NoError(t, err)
	err = engine.Close()
	require.NoError(t, err)

	pprof.Handler("/")
	go http.ListenAndServe("127.0.0.1:8080", nil)

	for i := 0; i < 1000; i++ {
		encoder := NewEncoder()

		opts := &Options{
			NoIterator: true,
			NoGarbage:  true,
		}
		sc, err := encoder.Encode(shellcode, 64, opts)
		require.NoError(t, err)
		// spew.Dump(shellcode)

		err = encoder.Close()
		require.NoError(t, err)

		if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
			return
		}
		addr := loadShellcode(t, sc)
		var val int
		ret, _, _ := syscall.SyscallN(addr, (uintptr)(unsafe.Pointer(&val)))
		require.Equal(t, 0x64, val)
		require.Equal(t, 0x64, int(ret))
	}
}

func TestEncoder(t *testing.T) {
	t.Run("x64", func(t *testing.T) {
		asm := ".code64\n"
		asm += "mov qword ptr [rcx], 0x64\n"
		asm += "mov rax, 0x64\n"
		asm += "ret\n"
		engine, err := keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_64)
		require.NoError(t, err)
		shellcode, err := engine.Assemble(asm, 0)
		require.NoError(t, err)
		err = engine.Close()
		require.NoError(t, err)

		encoder := NewEncoder()
		opts := &Options{
			NoIterator: true,
			NoGarbage:  true,
		}
		shellcode, err = encoder.Encode(shellcode, 64, opts)
		require.NoError(t, err)
		spew.Dump(shellcode)

		err = encoder.Close()
		require.NoError(t, err)

		if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
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
		engine, err := keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_32)
		require.NoError(t, err)
		shellcode, err := engine.Assemble(asm, 0)
		require.NoError(t, err)
		err = engine.Close()
		require.NoError(t, err)

		encoder := NewEncoder()
		shellcode, err = encoder.Encode(shellcode, 32, nil)
		require.NoError(t, err)
		spew.Dump(shellcode)

		err = encoder.Close()
		require.NoError(t, err)

		if runtime.GOOS != "windows" || runtime.GOARCH != "386" {
			return
		}
		addr := loadShellcode(t, shellcode)
		var val int
		ret, _, _ := syscall.SyscallN(addr, (uintptr)(unsafe.Pointer(&val)))
		require.Equal(t, 0x86, int(ret))
	})
}
