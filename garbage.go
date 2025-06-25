package ssce

import (
	"bytes"
	"embed"
	"fmt"
	"io"
	"io/fs"
	"text/template"
)

// The role of the junk code is to make the instruction sequence
// as featureless as possible.
var (
	//go:embed junk/*_x86.asm
	defaultJunkCodeFSX86 embed.FS

	//go:embed junk/*_x64.asm
	defaultJunkCodeFSX64 embed.FS

	defaultJunkCodeX86 = readJunkCodeTemplates(defaultJunkCodeFSX86)
	defaultJunkCodeX64 = readJunkCodeTemplates(defaultJunkCodeFSX64)
)

func readJunkCodeTemplates(efs embed.FS) []string {
	var templates []string
	err := fs.WalkDir(efs, ".", func(_ string, entry fs.DirEntry, _ error) error {
		if entry.IsDir() {
			return nil
		}
		file, err := efs.Open(entry.Name())
		if err != nil {
			panic(err)
		}
		data, err := io.ReadAll(file)
		if err != nil {
			panic(err)
		}
		templates = append(templates, string(data))
		return nil
	})
	if err != nil {
		panic(err)
	}
	return templates
}

type junkCodeCtx struct {
	// for replace registers
	Reg map[string]string
}

// the output garbage instruction length is no limit.
func (e *Encoder) garbageInst() []byte {
	if e.opts.NoGarbage {
		return nil
	}
	switch e.rand.Intn(4) {
	case 0:
		return nil
	case 1:
		return e.garbageJumpShort(2, 16)
	case 2:
		return e.garbageMultiByteNOP()
	case 3:
		return e.garbageTemplate()
	default:
		panic("invalid garbage instruction selection")
	}
}

// the output garbage instruction length is <= 7 bytes.
func (e *Encoder) garbageInstShort() []byte {
	if e.opts.NoGarbage {
		return nil
	}
	switch e.rand.Intn(3) {
	case 0:
		return nil
	case 1:
		return e.garbageJumpShort(2, 5)
	case 2:
		return e.garbageMultiByteNOP()
	default:
		panic("invalid garbage instruction selection")
	}
}

// 0xEB, rel, [min, max] random bytes.
func (e *Encoder) garbageJumpShort(min, max int) []byte {
	if min < 1 || max > 127 {
		panic("garbage jump short length out of range")
	}
	jmp := make([]byte, 0, 1+max/2)
	offset := min + e.rand.Intn(max-min+1)
	jmp = append(jmp, 0xEB, byte(offset))
	jmp = append(jmp, e.randBytes(offset)...)
	return jmp
}

func (e *Encoder) garbageMultiByteNOP() []byte {
	var nop []byte
	switch e.rand.Intn(2) {
	case 0:
		nop = []byte{0x90}
	case 1:
		nop = []byte{0x66, 0x90}
	}
	return nop
}

func (e *Encoder) garbageTemplate() []byte {
	var junkCodes []string
	switch e.arch {
	case 32:
		junkCodes = e.getJunkCodeX86()
	case 64:
		junkCodes = e.getJunkCodeX64()
	}
	// select random junk code template
	idx := e.rand.Intn(len(junkCodes))
	junkCode := junkCodes[idx]
	// process assembly source
	tpl, err := template.New("junk_code").Funcs(template.FuncMap{
		"dr": e.registerDWORD,
	}).Parse(junkCode)
	if err != nil {
		panic("invalid junk code template")
	}
	ctx := junkCodeCtx{
		Reg: e.buildRandomRegisterMap(),
	}
	buf := bytes.NewBuffer(make([]byte, 0, 512))
	err = tpl.Execute(buf, &ctx)
	if err != nil {
		panic(fmt.Sprintf("failed to build junk code assembly source: %s", err))
	}
	// assemble junk code
	inst, err := e.engine.Assemble(buf.String(), 0)
	if err != nil {
		panic(fmt.Sprintf("failed to assemble junk code: %s", err))
	}
	return inst
}
