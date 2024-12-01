package ssce

import (
	"bytes"
	"fmt"
	"runtime"
	"testing"
	"unsafe"

	"github.com/For-ACGN/go-keystone"
	"github.com/davecgh/go-spew/spew"
	"github.com/stretchr/testify/require"
)

func TestEncoder(t *testing.T) {
	encoder := NewEncoder(0)
	fmt.Println("seed:", encoder.Seed())

	t.Run("x86", func(t *testing.T) {
		asm := ".code32\n"
		asm += "mov eax, dword ptr [esp+4]\n"
		asm += "mov dword ptr [eax], 0x86\n"
		asm += "mov eax, 0x86\n"
		asm += "ret\n"
		engine, err := keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_32)
		require.NoError(t, err)
		shellcode, err := engine.Assemble(asm, 0)
		require.NoError(t, err)
		err = engine.Close()
		require.NoError(t, err)

		opts := &Options{
			EraseInst:  true,
			NoIterator: true,
			NoGarbage:  true,
		}
		shellcode, err = encoder.Encode(shellcode, 32, opts)
		require.NoError(t, err)

		spew.Dump(shellcode)
		num := bytes.Count(shellcode, []byte{0x00, 0x00, 0x00})
		require.Less(t, num, 2)
		num = bytes.Count(shellcode, []byte{0xFF, 0xFF, 0xFF})
		require.Less(t, num, 1)

		if runtime.GOOS != "windows" || runtime.GOARCH != "386" {
			return
		}
		addr := loadShellcode(t, shellcode)
		var val int
		ret, _, _ := syscallN(addr, (uintptr)(unsafe.Pointer(&val)))
		require.Equal(t, 0x86, int(ret))
		require.Equal(t, 0x86, val)

		// check shellcode is erased
		sc := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(shellcode))
		require.False(t, bytes.Contains(sc, shellcode))

		spew.Dump(shellcode)
		num = bytes.Count(shellcode, []byte{0x00, 0x00, 0x00})
		require.Less(t, num, 2)
		num = bytes.Count(shellcode, []byte{0xFF, 0xFF, 0xFF})
		require.Less(t, num, 1)
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
			EraseInst:  true,
			NoIterator: true,
			NoGarbage:  true,
		}
		shellcode, err = encoder.Encode(shellcode, 64, opts)
		require.NoError(t, err)

		testFindSignature(t, shellcode)
		spew.Dump(shellcode)

		if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
			return
		}
		addr := loadShellcode(t, shellcode)
		var val int
		ret, _, _ := syscallN(addr, (uintptr)(unsafe.Pointer(&val)))
		require.Equal(t, 0x64, int(ret))
		require.Equal(t, 0x64, val)

		// check shellcode is erased
		sc := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(shellcode))
		require.False(t, bytes.Contains(sc, shellcode))
		testFindSignature(t, sc)
	})

	err := encoder.Close()
	require.NoError(t, err)
}

func TestMinifyMode(t *testing.T) {
	encoder := NewEncoder(0)
	fmt.Println("seed:", encoder.Seed())

	t.Run("x86", func(t *testing.T) {
		asm := ".code32\n"
		asm += "mov eax, dword ptr [esp+4]\n"
		asm += "mov dword ptr [eax], 0x86\n"
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
			NoGarbage:  true,
		}
		shellcode, err = encoder.Encode(shellcode, 32, opts)
		require.NoError(t, err)

		spew.Dump(shellcode)
		num := bytes.Count(shellcode, []byte{0x00, 0x00, 0x00})
		require.Less(t, num, 2)
		num = bytes.Count(shellcode, []byte{0xFF, 0xFF, 0xFF})
		require.Less(t, num, 1)

		if runtime.GOOS != "windows" || runtime.GOARCH != "386" {
			return
		}
		addr := loadShellcode(t, shellcode)
		var val int
		ret, _, _ := syscallN(addr, (uintptr)(unsafe.Pointer(&val)))
		require.Equal(t, 0x86, int(ret))
		require.Equal(t, 0x86, val)
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
			MinifyMode: true,
			NoIterator: true,
			NoGarbage:  true,
		}
		shellcode, err = encoder.Encode(shellcode, 64, opts)
		require.NoError(t, err)

		testFindSignature(t, shellcode)
		spew.Dump(shellcode)

		if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
			return
		}
		addr := loadShellcode(t, shellcode)
		var val int
		ret, _, _ := syscallN(addr, (uintptr)(unsafe.Pointer(&val)))
		require.Equal(t, 0x64, int(ret))
		require.Equal(t, 0x64, val)
	})

	err := encoder.Close()
	require.NoError(t, err)
}

func TestEncoderFuzz(t *testing.T) {
	encoder := NewEncoder(0)
	fmt.Println("seed:", encoder.Seed())

	t.Run("x86", func(t *testing.T) {
		asm := ".code32\n"
		asm += "mov eax, dword ptr [esp+4]\n"
		asm += "mov dword ptr [eax], 0x86\n"
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
				SaveContext: true,
				EraseInst:   true,
			}
			output, err := encoder.Encode(shellcode, 32, opts)
			require.NoError(t, err)
			testFindSignature(t, output)

			if runtime.GOOS != "windows" || runtime.GOARCH != "386" {
				continue
			}
			addr := loadShellcode(t, output)
			var val int
			_, _, _ = syscallN(addr, (uintptr)(unsafe.Pointer(&val)))
			require.Equal(t, 0x86, val)

			// check shellcode is erased
			sc := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(output))
			require.False(t, bytes.Contains(sc, shellcode))
			testFindSignature(t, sc)
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
			testFindSignature(t, output)

			if runtime.GOOS != "windows" || runtime.GOARCH != "amd64" {
				continue
			}
			addr := loadShellcode(t, output)
			var val int
			ret, _, _ := syscallN(addr, (uintptr)(unsafe.Pointer(&val)))
			require.Equal(t, int(addr), int(ret))
			require.Equal(t, 0x64, val)

			// check shellcode is erased
			sc := unsafe.Slice((*byte)(unsafe.Pointer(addr)), len(output))
			require.False(t, bytes.Contains(sc, shellcode))
			testFindSignature(t, sc)
		}
	})

	err := encoder.Close()
	require.NoError(t, err)
}

func testFindSignature(t *testing.T, data []byte) {
	msg := "found call short or jump near\n"
	msg += spew.Sdump(data)
	// not appear call
	require.False(t, bytes.Contains(data, []byte{0x00, 0x00, 0x00}), msg)
	// not appear jump near
	require.False(t, bytes.Contains(data, []byte{0xFF, 0xFF, 0xFF}), msg)
}
