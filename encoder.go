package ssce

import (
	"bytes"
	cr "crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"math"
	"math/rand"
	"strings"
	"text/template"
	"time"

	"github.com/For-ACGN/go-keystone"
)

var (
	registerX86 = []string{
		"eax", "ebx", "ecx", "edx",
		"ebp", "esi", "edi",
	}

	registerX64 = []string{
		"rax", "rbx", "rcx", "rdx",
		"rbp", "rsi", "rdi",
	}
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
	stubKey any

	// save and restore context
	contextSeq []int

	// for select random register
	regBox []string
}

// Options contains options about encode shellcode.
type Options struct {
	// the number of the iterator
	NumIterator int

	// the size of the garbage instruction at tail
	NumTailInst int

	// only use the mini loader, not use loader
	// for erase shellcode and more feature
	MinifyMode bool

	// save and restore context after call shellcode
	SaveContext bool

	// erase loader instruction and shellcode after call it
	EraseInst bool

	// disable iterator, not recommend
	NoIterator bool

	// disable garbage instruction, not recommend
	NoGarbage bool

	// specify a random seed for encoder
	RandSeed int64

	// trim the seed at the tail of output
	TrimSeed bool

	// specify the x86 mini decoder template
	MiniDecoderX86 string

	// specify the x64 mini decoder template
	MiniDecoderX64 string

	// specify the x86 loader template
	LoaderX86 string

	// specify the x64 loader template
	LoaderX64 string

	// specify the x86 junk code templates
	JunkCodeX86 []string

	// specify the x64 junk code templates
	JunkCodeX64 []string
}

// NewEncoder is used to create a simple shellcode encoder.
func NewEncoder() *Encoder {
	var seed int64
	buf := make([]byte, 8)
	_, err := cr.Read(buf)
	if err == nil {
		seed = int64(binary.LittleEndian.Uint64(buf)) // #nosec G115
	} else {
		seed = time.Now().UTC().UnixNano()
	}
	rng := rand.New(rand.NewSource(seed)) // #nosec
	encoder := Encoder{
		seed: rng.Int63(),
		rand: rng,
	}
	return &encoder
}

// Encode is used to encode input shellcode to a unique shellcode.
func (e *Encoder) Encode(shellcode []byte, arch int, opts *Options) (output []byte, err error) {
	defer func() {
		if r := recover(); r != nil {
			err = errors.New(fmt.Sprint(r))
		}
	}()
	if len(shellcode) == 0 {
		return nil, errors.New("empty shellcode")
	}
	if opts == nil {
		opts = new(Options)
	}
	e.arch = arch
	e.opts = opts
	// initialize keystone engine
	err = e.initAssembler()
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
		seed = e.rand.Int63()
	}
	e.rand.Seed(seed)
	// record the last seed
	e.seed = seed
	// encode the raw shellcode and add loader
	output, err = e.addLoader(shellcode)
	if err != nil {
		return nil, err
	}
	// insert mini decoder at the prefix
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
	// append the random seed to tail
	if !opts.TrimSeed {
		buf := binary.BigEndian.AppendUint64(nil, uint64(seed)) // #nosec G115
		output = append(output, buf...)
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
	}
	if err != nil {
		return err
	}
	return e.engine.Option(keystone.OPT_SYNTAX, keystone.OPT_SYNTAX_INTEL)
}

func (e *Encoder) assemble(src string) ([]byte, error) {
	if strings.Contains(src, "<no value>") {
		return nil, errors.New("invalid register in assembly source")
	}
	return e.engine.Assemble(src, 0)
}

func (e *Encoder) addLoader(shellcode []byte) ([]byte, error) {
	if e.opts.MinifyMode {
		return shellcode, nil
	}
	// append instructions for "IV" about encoder
	shellcode = append(e.garbageInst(), shellcode...)
	// append instructions to tail for prevent brute-force
	tail := e.randBytes(64 + len(shellcode)/40)
	shellcode = append(shellcode, tail...)
	// generate crypto key for shellcode decoder
	cryptoKey := e.randBytes(32)
	var (
		loader    string
		stubKey   any
		eraserLen int
	)
	switch e.arch {
	case 32:
		loader = e.getLoaderX86()
		stubKey = e.rand.Uint32()
		eraserLen = len(eraserX86) + e.rand.Intn(len(cryptoKey))
		shellcode = encrypt32(shellcode, cryptoKey)
	case 64:
		loader = e.getLoaderX64()
		stubKey = e.rand.Uint64()
		eraserLen = len(eraserX64) + e.rand.Intn(len(cryptoKey))
		shellcode = encrypt64(shellcode, cryptoKey)
	}
	e.key = cryptoKey
	e.stubKey = stubKey
	// parse loader template
	tpl, err := template.New("loader").Funcs(template.FuncMap{
		"db":  toDB,
		"hex": toHex,
		"igi": e.insertGarbageInst,
	}).Parse(loader)
	if err != nil {
		return nil, fmt.Errorf("invalid assembly source template: %s", err)
	}
	ctx := loaderCtx{
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
	// build source from template and assemble it
	buf := bytes.NewBuffer(make([]byte, 0, 4096))
	err = tpl.Execute(buf, &ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build assembly source: %s", err)
	}
	inst, err := e.assemble(buf.String())
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
		miniDecoder = e.getMiniDecoderX86()
	case 64:
		miniDecoder = e.getMiniDecoderX64()
	}
	// parse mini decoder template
	tpl, err := template.New("mini_decoder").Funcs(template.FuncMap{
		"db":  toDB,
		"hex": toHex,
		"dr":  toRegDWORD,
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
	numLoopStub := int32(len(body)/4) ^ numLoopMaskA ^ numLoopMaskB // #nosec G115
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

		Reg: e.buildRandomRegisterMap(),
	}
	// add padding data at tail of mini decoder
	if !e.opts.MinifyMode {
		ctx.Padding = true
		ctx.PadData = e.randBytes(8 + e.rand.Intn(48))
	}
	// build source from template and assemble it
	buf := bytes.NewBuffer(make([]byte, 0, 512))
	err = tpl.Execute(buf, &ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to build assembly source: %s", err)
	}
	inst, err := e.assemble(buf.String())
	if err != nil {
		return nil, err
	}
	return append(inst, body...), nil
}

func (e *Encoder) getMiniDecoderX86() string {
	if e.opts.MiniDecoderX86 != "" {
		return e.opts.MiniDecoderX86
	}
	return defaultMiniDecoderX86
}

func (e *Encoder) getMiniDecoderX64() string {
	if e.opts.MiniDecoderX64 != "" {
		return e.opts.MiniDecoderX64
	}
	return defaultMiniDecoderX64
}

func (e *Encoder) getLoaderX86() string {
	if e.opts.LoaderX86 != "" {
		return e.opts.LoaderX86
	}
	return defaultLoaderX86
}

func (e *Encoder) getLoaderX64() string {
	if e.opts.LoaderX64 != "" {
		return e.opts.LoaderX64
	}
	return defaultLoaderX64
}

func (e *Encoder) getJunkCodeX86() []string {
	if len(e.opts.JunkCodeX86) > 0 {
		return e.opts.JunkCodeX86
	}
	return defaultJunkCodeX86
}

func (e *Encoder) getJunkCodeX64() []string {
	if len(e.opts.JunkCodeX64) > 0 {
		return e.opts.JunkCodeX64
	}
	return defaultJunkCodeX64
}

func (e *Encoder) randBytes(n int) []byte {
	buf := make([]byte, n)
	_, _ = e.rand.Read(buf)
	return buf
}

func (e *Encoder) buildRandomRegisterMap() map[string]string {
	e.initRegisterBox()
	register := make(map[string]string, 16)
	switch e.arch {
	case 32:
		for _, reg := range registerX86 {
			register[reg] = e.selectRegister()
		}
	case 64:
		for _, reg := range registerX64 {
			register[reg] = e.selectRegister()
		}
	}
	return register
}

func (e *Encoder) initRegisterBox() {
	var reg []string
	switch e.arch {
	case 32:
		reg = make([]string, len(registerX86))
		copy(reg, registerX86)
	case 64:
		reg = make([]string, len(registerX64))
		copy(reg, registerX64)
	}
	e.regBox = reg
}

// selectRegister is used to make sure each register will be selected once.
func (e *Encoder) selectRegister() string {
	idx := e.rand.Intn(len(e.regBox))
	reg := e.regBox[idx]
	// remove selected register
	e.regBox = append(e.regBox[:idx], e.regBox[idx+1:]...)
	return reg
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
