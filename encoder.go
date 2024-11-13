package ssce

import (
	"bytes"
	"errors"
	"fmt"
	"math/rand"
	"text/template"
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
	// encode the raw shellcode
	output, err := e.encode(shellcode)
	if err != nil {
		return nil, err
	}

	// iterate the encoding of the pre-decoder and part of the shellcode
	decoder := len(output) - e.rand.Intn(len(shellcode))
	times := 4 + e.rand.Intn(8)
	for i := 0; i < times; i++ {
		input := output[:decoder]
		newOutput, err := e.encode(input)
		if err != nil {
			return nil, err
		}
		output = append(newOutput, output[decoder:]...)
		decoder = len(newOutput) - e.rand.Intn(len(input))
	}

	// padding garbage at the tail
	times = 4 + e.rand.Intn(16)
	for i := 0; i < times; i++ {
		var garbage []byte
		switch e.rand.Intn(3) {
		case 0:
			garbage = e.randBytes(e.rand.Intn(24))
		case 1, 2:
			garbage = e.randString(e.rand.Intn(16))
		}
		output = append(output, garbage...)
	}
	return output, nil
}

func (e *Encoder) encode(shellcode []byte) ([]byte, error) {
	tpl, err := template.New("asm_src").Funcs(template.FuncMap{
		"db":  toDB,
		"hex": toHex,
		"igi": func() string {
			return ";" + toDB(e.genGarbageInst())
		},
	}).Parse(x64asm)
	if err != nil {
		return nil, fmt.Errorf("invalid assembly source template: %s", err)
	}
	cryptoKey := e.randBytes(32)
	shellcode = encrypt(shellcode, cryptoKey)
	jump := e.genGarbageJumpShort(64)
	save := e.saveContext()
	restore := e.restoreContext()
	ctx := asmContext{
		JumpShort:      jump,
		SaveContext:    save,
		RestoreContext: restore,
		DecryptorStub:  x64Decoder,
		CleanerStub:    nil,
		CryptoKey:      cryptoKey,
		CryptoKeyLen:   len(cryptoKey),
		Shellcode:      shellcode,
		ShellcodeLen:   len(shellcode),
	}
	buf := bytes.NewBuffer(make([]byte, 0, 2048+5*len(shellcode)))
	err = tpl.Execute(buf, &ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build assembly source: %s", err)
	}
	inst, err := e.engine.Assemble(buf.String(), 0)
	if err != nil {
		return nil, err
	}
	return inst, nil
}

// Close is used to close shellcode encoder.
func (e *Encoder) Close() error {
	return e.engine.Close()
}
