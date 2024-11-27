package ssce

import (
	"bytes"
	"runtime"
	"syscall"
	"testing"
	"unsafe"

	"github.com/For-ACGN/go-keystone"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestEncoder(t *testing.T) {
	encoder := NewEncoder()

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

		opts := &Options{
			MinifyMode: true,
			NoIterator: true,
			NoGarbage:  false,
		}
		shellcode, err = encoder.Encode(shellcode, 32, opts)
		require.NoError(t, err)
		spew.Dump(shellcode)

		if runtime.GOOS != "windows" || runtime.GOARCH != "386" {
			return
		}
		addr := loadShellcode(t, shellcode)
		var val int
		ret, _, _ := syscall.SyscallN(addr, (uintptr)(unsafe.Pointer(&val)))
		require.Equal(t, 0x86, int(ret))
	})

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

		opts := &Options{
			MinifyMode: false,
			NoIterator: true,
			NoGarbage:  false,
		}
		shellcode, err = encoder.Encode(shellcode, 64, opts)
		require.NoError(t, err)
		spew.Dump(shellcode)

		if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
			return
		}
		addr := loadShellcode(t, shellcode)
		var val int
		ret, _, _ := syscall.SyscallN(addr, (uintptr)(unsafe.Pointer(&val)))
		require.Equal(t, 0x64, val)
		require.Equal(t, 0x64, int(ret))
	})

	err := encoder.Close()
	require.NoError(t, err)
}

func TestEncoderFuzz(t *testing.T) {
	encoder := NewEncoder()

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

		for i := 0; i < 100; i++ {
			opts := &Options{
				MinifyMode:  true,
				SaveContext: true,
				EraseInst:   true,
			}
			output, err := encoder.Encode(shellcode, 32, opts)
			require.NoError(t, err)
			testCheckOutput(t, output)

			if runtime.GOOS != "windows" || runtime.GOARCH != "386" {
				continue
			}
			addr := loadShellcode(t, output)
			// var val int
			// ret, _, _ := syscall.SyscallN(addr, (uintptr)(unsafe.Pointer(&val)))
			// // TODO require.Equal(t, 0x86, val)
			// require.Equal(t, int(addr), int(ret))

			// check shellcode is erased
			sc := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(output))
			require.False(t, bytes.Contains(sc, shellcode))
		}
	})

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

		for i := 0; i < 100; i++ {
			opts := &Options{
				SaveContext: true,
				EraseInst:   true,
			}
			output, err := encoder.Encode(shellcode, 64, opts)
			require.NoError(t, err)
			testCheckOutput(t, output)

			if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
				continue
			}
			addr := loadShellcode(t, output)
			var val int
			ret, _, _ := syscall.SyscallN(addr, (uintptr)(unsafe.Pointer(&val)))
			require.Equal(t, 0x64, val)
			require.Equal(t, int(addr), int(ret))

			// check shellcode is erased
			sc := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(output))
			require.False(t, bytes.Contains(sc, shellcode))
		}
	})

	err := encoder.Close()
	require.NoError(t, err)
}

func testCheckOutput(t *testing.T, output []byte) {
	// not appear call
	require.False(t, bytes.Contains(output, []byte{0x00, 0x00, 0x00}), "find call short")
	// not appear jump near
	require.False(t, bytes.Contains(output, []byte{0xFF, 0xFF, 0xFF}), "find jump near")
}
