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
	engine32 *keystone.Engine
	engine64 *keystone.Engine
	rand     *rand.Rand

	contextSeq []int
}

// Options contains options about Encode.
type Options struct {
	SaveContext bool // not break registers
}

// NewEncoder is used to create a simple shellcode encoder.
func NewEncoder() (*Encoder, error) {
	var ok bool
	engine32, err := keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_32)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !ok {
			_ = engine32.Close()
		}
	}()
	engine64, err := keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_64)
	if err != nil {
		return nil, err
	}
	defer func() {
		if !ok {
			_ = engine64.Close()
		}
	}()
	err = engine32.Option(keystone.OPT_SYNTAX, keystone.OPT_SYNTAX_INTEL)
	if err != nil {
		return nil, err
	}
	err = engine64.Option(keystone.OPT_SYNTAX, keystone.OPT_SYNTAX_INTEL)
	if err != nil {
		return nil, err
	}
	rd := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
	encoder := Encoder{
		engine32: engine32,
		engine64: engine64,
		rand:     rd,
	}
	ok = true
	return &encoder, nil
}

// Encode is used to encode input shellcode to a unique shellcode.
func (e *Encoder) Encode(shellcode []byte, arch int, opts *Options) ([]byte, error) {
	if len(shellcode) == 0 {
		return nil, errors.New("empty shellcode")
	}
	if opts == nil {
		opts = new(Options)
	}
	// append tail for prevent brute-force
	tail := e.randBytes(64 + len(shellcode)/10)
	shellcode = append(shellcode, tail...)
	// encode the raw shellcode
	output, err := e.encode(shellcode, arch, opts)
	if err != nil {
		return nil, err
	}
	// iterate the encoding of the pre-decoder and part of the shellcode
	divider := e.rand.Intn(len(output))
	times := 4 + e.rand.Intn(8)
	for i := 0; i < times; i++ {
		input := output[:divider]
		newOutput, err := e.encode(input, arch, opts)
		if err != nil {
			return nil, err
		}
		output = append(newOutput, output[divider:]...)
		divider = e.rand.Intn(len(newOutput))
	}
	// padding garbage at the tail
	times = 8 + e.rand.Intn(32)
	for j := 0; j < times; j++ {
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

func (e *Encoder) encode(shellcode []byte, arch int, opts *Options) ([]byte, error) {
	var engine *keystone.Engine
	switch arch {
	case 32:
		engine = e.engine32
	case 64:
		engine = e.engine64
	default:
		return nil, errors.New("invalid architecture")
	}
	tpl, err := template.New("asm_src").Funcs(template.FuncMap{
		"db":  toDB,
		"hex": toHex,
		"igi": func() string {
			return ";" + toDB(e.garbageInst())
		},
	}).Parse(x64asm)
	if err != nil {
		return nil, fmt.Errorf("invalid assembly source template: %s", err)
	}
	cryptoKey := e.randBytes(32)
	shellcode = encrypt(shellcode, cryptoKey)
	jump := e.garbageJumpShort(64)
	ctx := asmContext{
		JumpShort:      jump,
		SaveContext:    nil,
		RestoreContext: nil,
		DecryptorStub:  x64Decoder,
		CleanerStub:    nil,
		CryptoKey:      cryptoKey,
		CryptoKeyLen:   len(cryptoKey),
		Shellcode:      shellcode,
		ShellcodeLen:   len(shellcode),
	}
	if opts.SaveContext {
		ctx.SaveContext = e.saveContext(arch)
		ctx.RestoreContext = e.restoreContext(arch)
	}
	buf := bytes.NewBuffer(make([]byte, 0, 2048+5*len(shellcode)))
	err = tpl.Execute(buf, &ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build assembly source: %s", err)
	}
	inst, err := engine.Assemble(buf.String(), 0)
	if err != nil {
		return nil, err
	}
	return inst, nil
}

// Close is used to close shellcode encoder.
func (e *Encoder) Close() error {
	err := e.engine32.Close()
	er := e.engine64.Close()
	if er != nil && err == nil {
		err = er
	}
	return err
}
