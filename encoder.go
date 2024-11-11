package ssce

import (
	"errors"
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
	output := make([]byte, 0, 512+len(shellcode))
	output = append(output, e.genGarbageJumpShort(64)...)
	output = append(output, e.saveContext()...)

	restore := e.restoreContext()

	output = append(output, restore...)
	output = append(output, shellcode...)
	return output, nil
}

// Close is used to close shellcode encoder.
func (e *Encoder) Close() error {
	return e.engine.Close()
}
