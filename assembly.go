package ssce

import (
	"embed"
	"encoding/hex"
	"fmt"
	"strings"
)

// just for prevent [import _ "embed"] :)
var _ embed.FS

// The role of the mini decoder is to eliminate the
// instruction sequence features as much as possible.
var (
	//go:embed asm/mini_decoder_x86.asm
	defaultMiniDecoderX86 string

	//go:embed asm/mini_decoder_x64.asm
	defaultMiniDecoderX64 string
)

type miniDecoderCtx struct {
	Seed any
	Key  any

	NumLoopStub  int32
	NumLoopMaskA int32
	NumLoopMaskB int32

	OffsetT int32
	OffsetA int32
	OffsetS int32

	// for replace registers
	Reg map[string]string

	// for prevent call short
	Padding bool
	PadData []byte
}

// The role of the shellcode loader is to execute the shellcode
// without destroying the CPU context, and to erase the loader
// before execution and the shellcode after execution.
var (
	//go:embed asm/loader_x86.asm
	defaultLoaderX86 string

	//go:embed asm/loader_x64.asm
	defaultLoaderX64 string
)

type loaderCtx struct {
	SaveContext    []byte
	RestoreContext []byte

	StubKey any

	DecoderStub   []byte
	EraserStub    []byte
	CryptoKeyStub []byte

	CryptoKeyLen int
	ShellcodeLen int
	EraserLen    int

	EraseShellcode bool
}

func toDB(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	builder := strings.Builder{}
	builder.WriteString(".byte ")
	for i := 0; i < len(b); i++ {
		builder.WriteString("0x")
		s := hex.EncodeToString([]byte{b[i]})
		builder.WriteString(strings.ToUpper(s))
		builder.WriteString(", ")
	}
	return builder.String()
}

func toHex(v any) string {
	return fmt.Sprintf("0x%X", v)
}
