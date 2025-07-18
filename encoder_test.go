package ssce

import (
	"bytes"
	"encoding/binary"
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

func TestSpecificSeed(t *testing.T) {
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
			SaveContext: true,
			EraseInst:   true,
		}

		encoder1 := NewEncoder(12345678)
		output1, err := encoder1.Encode(shellcode, 32, opts)
		require.NoError(t, err)
		encoder2 := NewEncoder(12345678)
		output2, err := encoder2.Encode(shellcode, 32, opts)
		require.NoError(t, err)
		require.Equal(t, output1, output2)

		encoder3 := NewEncoder(13548971)
		opts.RandSeed = 12345678
		output3, err := encoder3.Encode(shellcode, 32, opts)
		require.NoError(t, err)
		require.Equal(t, output1, output3)

		seed := binary.BigEndian.Uint64(output3[len(output3)-8:])
		require.Equal(t, uint64(12345678), seed)
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
			SaveContext: true,
			EraseInst:   true,
		}

		encoder1 := NewEncoder(12345678)
		output1, err := encoder1.Encode(shellcode, 64, opts)
		require.NoError(t, err)
		encoder2 := NewEncoder(12345678)
		output2, err := encoder2.Encode(shellcode, 64, opts)
		require.NoError(t, err)
		require.Equal(t, output1, output2)

		encoder3 := NewEncoder(13548971)
		opts.RandSeed = 12345678
		output3, err := encoder3.Encode(shellcode, 64, opts)
		require.NoError(t, err)
		require.Equal(t, output1, output3)

		seed := binary.BigEndian.Uint64(output3[len(output3)-8:])
		require.Equal(t, uint64(12345678), seed)
	})
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
	msg := "found signature\n"
	msg += spew.Sdump(data)
	require.Less(t, bytes.Count(data, []byte{0x00, 0x00, 0x00}), 3, msg)
	require.Less(t, bytes.Count(data, []byte{0xFF, 0xFF, 0xFF}), 3, msg)
}
