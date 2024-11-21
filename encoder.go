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

	// context arguments
	arch int
	opts *Options
	key  []byte

	// for xor stubs
	decoderStubKey   interface{}
	eraserStubKey    interface{}
	cryptoKeyStubKey interface{}

	// save and restore context
	contextSeq []int
}

// Options contains options about Encode.
type Options struct {
	NumIterator int
	NumTailInst int
	SaveContext bool
	EraseInst   bool
	NoIterator  bool
	NoGarbage   bool
}

// New is used to create a simple shellcode encoder.
func New() (*Encoder, error) {
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
	numIter := opts.NumIterator
	if numIter < 1 {
		numIter = 2 + e.rand.Intn(4)
	}
	if opts.NoIterator {
		numIter = 0
	}
	for i := 0; i < numIter; i++ {
		output, err = e.encode(output, arch, opts)
		if err != nil {
			return nil, err
		}
	}
	// padding garbage at the tail
	times := 8 + e.rand.Intn((numIter+1)*16)
	if !opts.NoGarbage {
		num := e.rand.Intn(16 * times)
		output = append(output, e.randBytes(num)...)
	}
	// append garbage data to tail for prevent brute-force
	output = append(output, e.randBytes(opts.NumTailInst)...)

	return output, nil
	// tpl, err := template.New("asm_src").Funcs(template.FuncMap{
	// 	"db":  toDB,
	// 	"hex": toHex,
	// 	"igi": e.insertGarbageInst,
	// }).Parse(x64XSRL)
	// if err != nil {
	// 	return nil, fmt.Errorf("invalid assembly source template: %s", err)
	// }
	//
	// key := e.rand.Uint64()
	// body := e.miniXOR(output, key)
	// ctx := headerContext{
	// 	NumLoop:   len(body) / 8,
	// 	CryptoKey: key,
	// }
	//
	// buf := bytes.NewBuffer(make([]byte, 0, 2048+5*len(shellcode)))
	// err = tpl.Execute(buf, &ctx)
	// if err != nil {
	// 	return nil, fmt.Errorf("failed to build assembly source: %s", err)
	// }
	//
	// // fmt.Println(buf)
	//
	// inst, err := e.engine64.Assemble(buf.String(), 0)
	// if err != nil {
	// 	return nil, err
	// }
	// return append(inst, body...), nil
}

func (e *Encoder) encode(shellcode []byte, arch int, opts *Options) ([]byte, error) {
	cryptoKey := e.randBytes(32)
	var (
		engine *keystone.Engine
		asmTpl string

		decoderStubKey   interface{}
		eraserStubKey    interface{}
		cryptoKeyStubKey interface{}
	)
	switch arch {
	case 32:
		engine = e.engine32
		asmTpl = x86asm
		shellcode = encrypt32(shellcode, cryptoKey)
		decoderStubKey = e.rand.Uint32()
		eraserStubKey = e.rand.Uint32()
		cryptoKeyStubKey = e.rand.Uint32()
	case 64:
		engine = e.engine64
		asmTpl = x64asm
		shellcode = encrypt64(shellcode, cryptoKey)
		decoderStubKey = e.rand.Uint64()
		eraserStubKey = e.rand.Uint64()
		cryptoKeyStubKey = e.rand.Uint64()
	default:
		return nil, errors.New("invalid architecture")
	}
	e.arch = arch
	e.opts = opts
	e.key = cryptoKey
	e.decoderStubKey = decoderStubKey
	e.eraserStubKey = eraserStubKey
	e.cryptoKeyStubKey = cryptoKeyStubKey

	tpl, err := template.New("asm_src").Funcs(template.FuncMap{
		"db":  toDB,
		"hex": toHex,
		"igi": e.insertGarbageInst,
	}).Parse(asmTpl)
	if err != nil {
		return nil, fmt.Errorf("invalid assembly source template: %s", err)
	}

	ctx := asmContext{
		JumpShort:        e.garbageJumpShort(64),
		SaveRegister:     e.saveContext(),
		RestoreRegister:  e.restoreContext(),
		DecoderStubKey:   decoderStubKey,
		EraserStubKey:    eraserStubKey,
		CryptoKeyStubKey: cryptoKeyStubKey,
		DecoderStub:      e.decoderStub(),
		EraserStub:       e.eraserStub(),
		CryptoKeyStub:    e.cryptoKeyStub(),
		CryptoKeyLen:     len(cryptoKey),
		ShellcodeLen:     len(shellcode),
	}
	if opts.SaveContext {
		ctx.SaveContext = e.saveContext()
		ctx.RestoreContext = e.restoreContext()
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
	inst = append(inst, shellcode...)
	return inst, nil
}

func (e *Encoder) insertGarbageInst() string {
	return ";" + toDB(e.garbageInst())
}

// Close is used to close shellcode encoder.
func (e *Encoder) Close() error {
	err0 := e.engine32.Close()
	err1 := e.engine64.Close()
	if err1 != nil && err0 == nil {
		err0 = err1
	}
	return err0
}
