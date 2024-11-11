package ssce

import (
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
	iv := e.randBytes(16)
	cipher := encrypt(append(iv, shellcode...), key)

	output := make([]byte, 0, 1024+len(shellcode))
	output = append(output, e.genGarbageJumpShort(64)...)
	output = append(output, e.saveContext()...)
	restore := e.restoreContext()

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
  lea rcx, [rbx + decoder + %X]
  mov rdx, %X
  mov r8,  [rbx + decoder + %X]
  mov r9, %X
  call decoder
decoder:
`

	src = fmt.Sprintf(src, len(x64Decoder), len(cipher), len(x64Decoder), len(key))

	fmt.Println(src)

	inst, err := e.engine.Assemble(src, 0)
	if err != nil {
		return nil, err
	}
	fmt.Println(inst)

	output = append(output, inst...)

	output = append(output, x64Decoder...)

	output = append(output, restore...)

	output = append(output, key...)
	output = append(output, cipher...)
	return output, nil
}

// Close is used to close shellcode encoder.
func (e *Encoder) Close() error {
	return e.engine.Close()
}
