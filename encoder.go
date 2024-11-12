package ssce

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/rand"
	"time"

	"github.com/For-ACGN/go-keystone"
)

// Encoder is a simple shellcode encoder.
type Encoder struct {
	arch int

	engine *keystone.Engine
	rand   *rand.Rand

	contextSeq []int
}

// NewEncoder is used to create a simple shellcode encoder.
func NewEncoder(arch int) (*Encoder, error) {
	var mode keystone.Mode
	switch arch {
	case 64:
		mode = keystone.MODE_64
	case 32:
		mode = keystone.MODE_32
	default:
		return nil, errors.New("invalid encoder architecture")
	}
	engine, err := keystone.NewEngine(keystone.ARCH_X86, mode)
	if err != nil {
		return nil, err
	}
	err = engine.Option(keystone.OPT_SYNTAX, keystone.OPT_SYNTAX_INTEL)
	if err != nil {
		return nil, err
	}
	rd := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
	encoder := Encoder{
		arch:   arch,
		engine: engine,
		rand:   rd,
	}
	return &encoder, nil
}

// Encode is used to encode input shellcode to a unique shellcode.
func (e *Encoder) Encode(shellcode []byte) ([]byte, error) {
	key := e.randBytes(32)
	cipher := encrypt(shellcode, key)

	output := make([]byte, 0, 1024+len(shellcode))
	output = append(output, e.genGarbageJumpShort(64)...)
	output = append(output, e.saveContext()...)
	restore := e.restoreContext()

	call0 := make([]byte, 1+4)
	call0[0] = 0xE8
	binary.LittleEndian.PutUint32(call0[1:], uint32(5+len(restore)+1))

	call1 := make([]byte, 1+4)
	call1[0] = 0xE8
	binary.LittleEndian.PutUint32(call1[1:], uint32(len(restore)+1+len(x64Decoder)))

	src := `
.code64

entry:
  call get_rip
  jmp next
get_rip:
  pop rbx
  push rbx
  ret
next:
  lea rcx, [rbx + EOF - 5 + 0x%X]
  mov rdx, 0x%X
  lea r8, [rbx + EOF - 5 + 0x%X]
  mov r9, 0x%X
EOF:
`
	cipherPtr := len(call0) + len(call1) + len(restore) + 1 + len(x64Decoder)
	keyPtr := len(call0) + len(call1) + len(restore) + 1 + len(x64Decoder) + len(cipher)
	src = fmt.Sprintf(src, cipherPtr, len(cipher), keyPtr, len(key))

	inst, err := e.engine.Assemble(src, 0)
	if err != nil {
		return nil, err
	}
	output = append(output, inst...)
	output = append(output, call0...)
	output = append(output, call1...)
	output = append(output, restore...)
	output = append(output, 0xC3)
	output = append(output, x64Decoder...)
	output = append(output, cipher...)
	output = append(output, key...)
	return output, nil
}

// Close is used to close shellcode encoder.
func (e *Encoder) Close() error {
	return e.engine.Close()
}
