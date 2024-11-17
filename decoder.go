package ssce

import (
	"encoding/binary"
	"fmt"
	"strings"
)

func (e *Encoder) decoderBuilder() string {
	var decoder []byte
	switch e.arch {
	case 32:
		decoder = x86Decoder
	case 64:
		decoder = x64Decoder
	}
	return e.instBuilder(decoder, "decoder_stub")
}

func (e *Encoder) eraserBuilder() string {
	var eraser []byte
	switch e.arch {
	case 32:
		eraser = x86Eraser
	case 64:
		eraser = x64Eraser
	}
	return e.instBuilder(eraser, "eraser_stub")
}

func (e *Encoder) cryptoKeyBuilder() string {
	return e.instBuilder(e.key, "crypto_key_stub")
}

func (e *Encoder) shellcodeBuilder() string {
	return e.instBuilder(e.sc, "shellcode_stub")
}

// lea reg, [rbx + offset + index]
// mov word ptr [reg], 0x1234
func (e *Encoder) instBuilder(inst []byte, offset string) string {
	switch e.arch {
	case 32:
		return e.instBuilder32(inst, offset)
	case 64:
		return e.instBuilder64(inst, offset)
	default:
		panic("invalid architecture")
	}
}

func (e *Encoder) instBuilder32(inst []byte, offset string) string {
	builder := strings.Builder{}
	return builder.String()
}

func (e *Encoder) selectOpSize32(rem int) int {
	var size []int
	switch {
	case rem < 2:
		size = []int{1}
	case rem < 4:
		size = []int{1, 2}
	default:
		size = []int{1, 2, 4}
	}
	return size[e.rand.Intn(len(size))]
}

func (e *Encoder) instBuilder64(inst []byte, offset string) string {
	builder := &strings.Builder{}
	registers := []string{
		"rax", "rcx", "rdx", "rsi", "rdi",
		"r8", "r9", "r10", "r11",
		"r12", "r13", "r14", "r15",
	}
	rem := len(inst)
	var index int
	for {
		if rem == 0 {
			break
		}
		opSize := e.selectOpSize64(rem)
		var (
			op string
			im uint
		)
		switch opSize {
		case 1:
			op = "byte"
			im = uint(inst[index])
		case 2:
			op = "word"
			im = uint(binary.LittleEndian.Uint16(inst[index:]))
		case 4:
			op = "dword"
			im = uint(binary.LittleEndian.Uint32(inst[index:]))
		case 8:
			im = uint(binary.LittleEndian.Uint64(inst[index:]))
		}
		addr := registers[e.rand.Intn(len(registers))]
		if opSize == 8 {
			var val string
			for {
				val = registers[e.rand.Intn(len(registers))]
				if val != addr {
					break
				}
			}
			asm := "  lea %s, [rbx + %s + 0x%X]"
			asm += e.insertGarbageInst() + "\n"
			_, _ = fmt.Fprintf(builder, asm, addr, offset, index)
			asm = "  mov %s, 0x%X"
			asm += e.insertGarbageInst() + "\n"
			_, _ = fmt.Fprintf(builder, asm, val, im)
			asm = "  mov [%s], %s"
			asm += e.insertGarbageInst() + "\n"
			_, _ = fmt.Fprintf(builder, asm, addr, val)
		} else {
			asm := "  lea %s, [rbx + %s + 0x%X]"
			asm += e.insertGarbageInst() + "\n"
			_, _ = fmt.Fprintf(builder, asm, addr, offset, index)
			asm = "  mov %s ptr [%s], 0x%X"
			asm += e.insertGarbageInst() + "\n"
			_, _ = fmt.Fprintf(builder, asm, op, addr, im)
		}
		rem -= opSize
		index += opSize
	}
	builder.WriteString("  ret" + e.insertGarbageInst() + "\n")
	return builder.String()
}

func (e *Encoder) selectOpSize64(rem int) int {
	var size []int
	switch {
	case rem < 2:
		size = []int{1}
	case rem < 4:
		size = []int{1, 2}
	case rem < 8:
		size = []int{1, 2, 4}
	default:
		size = []int{1, 2, 4, 8}
	}
	return size[e.rand.Intn(len(size))]
}

func (e *Encoder) decoderStub() []byte {
	var decoder []byte
	switch e.arch {
	case 32:
		decoder = x86Decoder
	case 64:
		decoder = x64Decoder
	}
	return e.randBytes(len(decoder))
}

func (e *Encoder) eraserStub() []byte {
	var eraser []byte
	switch e.arch {
	case 32:
		eraser = x86Eraser
	case 64:
		eraser = x64Eraser
	}
	return e.randBytes(len(eraser))
}

func (e *Encoder) cryptoKeyStub() []byte {
	return e.randBytes(len(e.key))
}

func (e *Encoder) shellcodeStub() []byte {
	return e.randBytes(len(e.sc))
}

func encrypt32(data, key []byte) []byte {
	output := make([]byte, len(data))
	last := binary.LittleEndian.Uint32(key[:4])
	ctr := binary.LittleEndian.Uint32(key[4:])
	keyIdx := int(last % uint32(len(key)))
	for i := 0; i < len(data); i++ {
		b := data[i]
		b ^= byte(last)
		b = rol(b, uint8(last%8))
		b ^= key[keyIdx]
		b += byte(ctr ^ last)
		b = ror(b, uint8(last%8))
		output[i] = b
		// update key index
		keyIdx++
		if keyIdx >= len(key) {
			keyIdx = 0
		}
		ctr++
		last = xorShift32(last)
	}
	return output
}

func encrypt64(data, key []byte) []byte {
	output := make([]byte, len(data))
	last := binary.LittleEndian.Uint64(key[:8])
	ctr := binary.LittleEndian.Uint64(key[8:])
	keyIdx := int(last % uint64(len(key)))
	for i := 0; i < len(data); i++ {
		b := data[i]
		b ^= byte(last)
		b = rol(b, uint8(last%8))
		b ^= key[keyIdx]
		b += byte(ctr ^ last)
		b = ror(b, uint8(last%8))
		output[i] = b
		// update key index
		keyIdx++
		if keyIdx >= len(key) {
			keyIdx = 0
		}
		ctr++
		last = xorShift64(last)
	}
	return output
}

func xorShift32(seed uint32) uint32 {
	seed ^= seed << 13
	seed ^= seed >> 17
	seed ^= seed << 5
	return seed
}

func xorShift64(seed uint64) uint64 {
	seed ^= seed << 13
	seed ^= seed >> 7
	seed ^= seed << 17
	return seed
}

func ror(value byte, bits uint8) byte {
	return value>>bits | value<<(8-bits)
}

func rol(value byte, bits uint8) byte {
	return value<<bits | value>>(8-bits)
}
