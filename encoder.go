package ssce

import (
	"bytes"
	cr "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/For-ACGN/go-keystone"
)

// Encoder is a simple shellcode encoder.
type Encoder struct {
	seed int64
	rand *rand.Rand

	// assembler
	engine *keystone.Engine

	// context arguments
	arch int
	opts *Options
	key  []byte

	// stub key for xor stubs
	stubKey interface{}

	// save and restore context
	contextSeq []int

	// for select random register
	regBox map[string]struct{}

	// for cover call short
	padding bool
}

// Options contains options about encode shellcode.
type Options struct {
	NumIterator int
	NumTailInst int
	MinifyMode  bool
	SaveContext bool
	EraseInst   bool
	NoIterator  bool
	NoGarbage   bool
	RandSeed    int64
}

// NewEncoder is used to create a simple shellcode encoder.
func NewEncoder(seed int64) *Encoder {
	if seed == 0 {
		buf := make([]byte, 8)
		_, err := cr.Read(buf)
		if err == nil {
			seed = int64(binary.LittleEndian.Uint64(buf))
		} else {
			seed = time.Now().UTC().UnixNano()
		}
	}
	rng := rand.New(rand.NewSource(seed)) // #nosec
	encoder := Encoder{
		seed: seed,
		rand: rng,
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
	// set random seed
	seed := opts.RandSeed
	if seed == 0 {
		seed = e.seed
	}
	e.rand.Seed(seed)
	// update default random seed
	e.seed = e.rand.Int63()
	// encode the raw shellcode and add loader
	output, err := e.addLoader(shellcode)
	if err != nil {
		return nil, err
	}
	// insert mini decoder at the prefix
	if !opts.MinifyMode {
		e.padding = true
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
	if !opts.NoGarbage {
		times := 8 + e.rand.Intn((numIter+1)*4)
		size := e.rand.Intn(16 * times)
		output = append(output, e.randBytes(size)...)
	}
	// append garbage data to tail for prevent brute-force
	output = append(output, e.randBytes(opts.NumTailInst)...)
	// append garbage data to the output shellcode prefix
	output = append(e.garbageInst(), output...)
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

func (e *Encoder) addLoader(shellcode []byte) ([]byte, error) {
	if e.opts.MinifyMode {
		return shellcode, nil
	}
	// append jump short for "IV" about encoder
	prefix := e.garbageJumpShort(8, 16)
	shellcode = append(prefix, shellcode...)
	// append instructions to tail for prevent brute-force
	tail := e.randBytes(64 + len(shellcode)/10)
	shellcode = append(shellcode, tail...)
	// generate crypto key for shellcode decoder
	cryptoKey := e.randBytes(32)
	var (
		loader    string
		stubKey   interface{}
		eraserLen int
	)
	switch e.arch {
	case 32:
		loader = x86Loader
		stubKey = e.rand.Uint32()
		eraserLen = len(x86Eraser) + e.rand.Intn(len(cryptoKey))
		shellcode = encrypt32(shellcode, cryptoKey)
	case 64:
		loader = x64Loader
		stubKey = e.rand.Uint64()
		eraserLen = len(x64Eraser) + e.rand.Intn(len(cryptoKey))
		shellcode = encrypt64(shellcode, cryptoKey)
	}
	e.key = cryptoKey
	e.stubKey = stubKey
	// create assembly source
	tpl, err := template.New("loader").Funcs(template.FuncMap{
		"db":  toDB,
		"hex": toHex,
		"igi": e.insertGarbageInst,
	}).Parse(loader)
	if err != nil {
		return nil, fmt.Errorf("invalid assembly source template: %s", err)
	}
	ctx := loaderCtx{
		JumpShort:      e.garbageJumpShort(16, 64),
		StubKey:        stubKey,
		DecoderStub:    e.decoderStub(),
		EraserStub:     e.eraserStub(),
		CryptoKeyStub:  e.cryptoKeyStub(),
		CryptoKeyLen:   len(cryptoKey),
		ShellcodeLen:   len(shellcode),
		EraserLen:      eraserLen,
		EraseShellcode: e.opts.EraseInst,
	}
	if e.opts.SaveContext {
		ctx.SaveContext = e.saveContext()
		ctx.RestoreContext = e.restoreContext()
	}
	buf := bytes.NewBuffer(make([]byte, 0, 4096))
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
	var miniDecoder string
	switch e.arch {
	case 32:
		miniDecoder = x86MiniDecoder
	case 64:
		miniDecoder = x64MiniDecoder
	}
	tpl, err := template.New("mini_decoder").Funcs(template.FuncMap{
		"db":  toDB,
		"hex": toHex,
		"dr":  e.registerDWORD,
		"igi": e.insertGarbageInst,
		"igs": e.insertGarbageInstShort,
	}).Parse(miniDecoder)
	if err != nil {
		return nil, fmt.Errorf("invalid assembly source template: %s", err)
	}
	seed := e.rand.Uint32()
	key := e.rand.Uint32()
	body := e.xsrl(input, seed, key)
	numLoopMaskA := e.rand.Int31()
	numLoopMaskB := e.rand.Int31()
	numLoopStub := int32(len(body)/4) ^ numLoopMaskA ^ numLoopMaskB
	offsetT := e.rand.Int31n(math.MaxInt32/4 - 4096)
	offsetA := e.rand.Int31n(math.MaxInt32/4 - 8192)
	offsetS := offsetT + offsetA
	e.initRegisterBox()
	ctx := miniDecoderCtx{
		Seed: seed,
		Key:  key,

		NumLoopStub:  numLoopStub,
		NumLoopMaskA: numLoopMaskA,
		NumLoopMaskB: numLoopMaskB,

		OffsetT: offsetT,
		OffsetA: offsetA,
		OffsetS: offsetS,

		Reg: e.buildRegisterBox(),

		Padding: e.padding,
	}
	if ctx.Padding {
		ctx.PadData = e.randBytes(8 + e.rand.Intn(48))
	}
	buf := bytes.NewBuffer(make([]byte, 0, 512))
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

func (e *Encoder) initRegisterBox() {
	switch e.arch {
	case 32:
		e.regBox = map[string]struct{}{
			"eax": {}, "ebx": {}, "ecx": {},
			"edx": {}, "esi": {}, "edi": {},
		}
	case 64:
		e.regBox = map[string]struct{}{
			"rax": {}, "rbx": {}, "rcx": {},
			"rdx": {}, "rsi": {}, "rdi": {},
			"r8": {}, "r9": {}, "r10": {}, "r11": {},
			"r12": {}, "r13": {}, "r14": {}, "r15": {},
		}
	}
}

func (e *Encoder) buildRegisterBox() map[string]string {
	register := make(map[string]string, 16)
	switch e.arch {
	case 32:
		for _, reg := range []string{
			"eax", "ebx", "ecx",
			"edx", "esi", "edi",
		} {
			register[reg] = e.selectRegister()
		}
	case 64:
		for _, reg := range []string{
			"rax", "rbx", "rcx",
			"rdx", "rsi", "rdi",
			"r8", "r9", "r10", "r11",
			"r12", "r13", "r14", "r15",
		} {
			register[reg] = e.selectRegister()
		}
	}
	return register
}

// selectRegister is used to make sure each register will be selected once.
func (e *Encoder) selectRegister() string {
	n := 1 + e.rand.Intn(1+len(e.regBox))
	var reg string
	for i := 0; i < n; i++ {
		for reg = range e.regBox {
		}
	}
	delete(e.regBox, reg)
	return reg
}

// convert r8 -> r8d, rax -> eax
func (e *Encoder) registerDWORD(reg string) string {
	_, err := strconv.Atoi(reg[1:])
	if err == nil {
		return reg + "d"
	}
	return strings.ReplaceAll(reg, "r", "e")
}

func (e *Encoder) insertGarbageInst() string {
	if e.opts.NoGarbage {
		return ""
	}
	return ";" + toDB(e.garbageInst())
}

func (e *Encoder) insertGarbageInstShort() string {
	if e.opts.NoGarbage {
		return ""
	}
	return ";" + toDB(e.garbageInstShort())
}

// Seed is used to get the random seed for debug.
func (e *Encoder) Seed() int64 {
	return e.seed
}

// Close is used to close shellcode encoder.
func (e *Encoder) Close() error {
	if e.engine == nil {
		return nil
	}
	return e.engine.Close()
}
