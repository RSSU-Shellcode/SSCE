package ssce

import (
	"bytes"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"text/template"
	"time"

	"github.com/For-ACGN/go-keystone"
)

// Encoder is a simple shellcode encoder.
type Encoder struct {
	rand *rand.Rand

	// assembler
	engine *keystone.Engine

	// context arguments
	arch int
	opts *Options
	key  []byte

	// stub keys for xor stubs
	decoderSK   interface{}
	eraserSK    interface{}
	cryptoKeySK interface{}

	// save and restore context
	contextSeq []int
}

// Options contains options about encode shellcode.
type Options struct {
	NumIterator int
	NumTailInst int
	SaveContext bool
	EraseInst   bool
	NoIterator  bool
	NoGarbage   bool
}

// NewEncoder is used to create a simple shellcode encoder.
func NewEncoder() *Encoder {
	rd := rand.New(rand.NewSource(time.Now().UTC().UnixNano()))
	encoder := Encoder{
		rand: rd,
	}
	return &encoder
}

// Encode is used to encode input shellcode to a unique shellcode.
func (e *Encoder) Encode(shellcode []byte, arch int, opts *Options) ([]byte, error) {
	if len(shellcode) == 0 {
		return nil, errors.New("empty shellcode")
	}
	if opts == nil {
		opts = new(Options)
	}
	e.arch = arch
	e.opts = opts
	// initialize keystone engine
	err := e.initAssembler()
	if err != nil {
		return nil, fmt.Errorf("failed to initialize assembler: %s", err)
	}
	defer func() {
		_ = e.engine.Close()
		e.engine = nil
	}()
	// append tail for prevent brute-force
	tail := e.randBytes(64 + len(shellcode)/10)
	shellcode = append(shellcode, tail...)
	// encode the raw shellcode
	output, err := e.encode(shellcode)
	if err != nil {
		return nil, err
	}
	output, err = e.addMiniDecoder(output)
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
		output, err = e.addMiniDecoder(output)
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

	err = e.engine.Close()
	if err != nil {
		return nil, err
	}
	return output, nil
}

func (e *Encoder) initAssembler() error {
	var err error
	switch e.arch {
	case 32:
		e.engine, err = keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_32)
	case 64:
		e.engine, err = keystone.NewEngine(keystone.ARCH_X86, keystone.MODE_64)
	default:
		return fmt.Errorf("invalid architecture: %d", e.arch)
	}
	if err != nil {
		return err
	}
	err = e.engine.Option(keystone.OPT_SYNTAX, keystone.OPT_SYNTAX_INTEL)
	if err != nil {
		return err
	}
	return nil
}

func (e *Encoder) encode(shellcode []byte) ([]byte, error) {
	cryptoKey := e.randBytes(32)
	var (
		asmTpl string

		decoderStubKey   interface{}
		eraserStubKey    interface{}
		cryptoKeyStubKey interface{}
	)
	switch e.arch {
	case 32:
		asmTpl = x86asm
		shellcode = encrypt32(shellcode, cryptoKey)
		decoderStubKey = e.rand.Uint32()
		eraserStubKey = e.rand.Uint32()
		cryptoKeyStubKey = e.rand.Uint32()
	case 64:
		asmTpl = x64asm
		shellcode = encrypt64(shellcode, cryptoKey)
		decoderStubKey = e.rand.Uint64()
		eraserStubKey = e.rand.Uint64()
		cryptoKeyStubKey = e.rand.Uint64()
	default:
		return nil, errors.New("invalid architecture")
	}
	e.key = cryptoKey
	e.decoderSK = decoderStubKey
	e.eraserSK = eraserStubKey
	e.cryptoKeySK = cryptoKeyStubKey

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
	if e.opts.SaveContext {
		ctx.SaveContext = e.saveContext()
		ctx.RestoreContext = e.restoreContext()
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
	inst = append(inst, shellcode...)
	return inst, nil
}

func (e *Encoder) addMiniDecoder(input []byte) ([]byte, error) {
	tpl, err := template.New("mini_decoder").Funcs(template.FuncMap{
		"db":  toDB,
		"hex": toHex,
		"igi": e.insertGarbageInst,
	}).Parse(x64MiniDecoder)
	if err != nil {
		return nil, fmt.Errorf("invalid assembly source template: %s", err)
	}
	seed := e.rand.Uint64()
	key := e.rand.Uint64()
	body := e.xsrl(input, seed, key)
	numLoopMaskA := e.rand.Int31()
	numLoopMaskB := e.rand.Int31()
	numLoopStub := int32(len(body)/8) ^ numLoopMaskA ^ numLoopMaskB
	offsetT := e.rand.Int31n(math.MaxInt32/4 - 4096)
	offsetA := e.rand.Int31n(math.MaxInt32/4 - 8192)
	offsetS := offsetT + offsetA
	ctx := miniDecoderCtx{
		Seed: seed,
		Key:  key,

		NumLoopStub:  numLoopStub,
		NumLoopMaskA: numLoopMaskA,
		NumLoopMaskB: numLoopMaskB,

		OffsetT: offsetT,
		OffsetA: offsetA,
		OffsetS: offsetS,
	}
	buf := bytes.NewBuffer(make([]byte, 0, 512+len(input)))
	err = tpl.Execute(buf, &ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build assembly source: %s", err)
	}
	inst, err := e.engine.Assemble(buf.String(), 0)
	if err != nil {
		return nil, err
	}
	return append(inst, body...), nil
}

func (e *Encoder) insertGarbageInst() string {
	if e.opts.NoGarbage {
		return ""
	}
	return ";" + toDB(e.garbageInst())
}

// Close is used to close shellcode encoder.
func (e *Encoder) Close() error {
	if e.engine == nil {
		return nil
	}
	return e.engine.Close()
}
