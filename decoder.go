package ssce

import (
	"bytes"
	"encoding/binary"
)

func (e *Encoder) decoderStub() []byte {
	var decoder []byte
	switch e.arch {
	case 32:
		decoder = decoderX86
	case 64:
		decoder = decoderX64
	}
	return e.miniXOR(decoder, e.stubKey)
}

func (e *Encoder) eraserStub() []byte {
	var eraser []byte
	switch e.arch {
	case 32:
		eraser = eraserX86
	case 64:
		eraser = eraserX64
	}
	return e.miniXOR(eraser, e.stubKey)
}

func (e *Encoder) cryptoKeyStub() []byte {
	return e.miniXOR(e.key, e.stubKey)
}

func (e *Encoder) miniXOR(inst []byte, key any) []byte {
	var output []byte
	switch e.arch {
	case 32:
		output = e.miniXOR32(inst, key.(uint32))
	case 64:
		output = e.miniXOR64(inst, key.(uint64))
	}
	return output
}

func (e *Encoder) miniXOR32(inst []byte, key uint32) []byte {
	// ensure the instructions length can be divisible by 4.
	inst = bytes.Clone(inst)
	numPad := len(inst) % 4
	if numPad != 0 {
		numPad = 4 - numPad
	}
	inst = append(inst, e.randBytes(numPad)...)
	for i := 0; i < len(inst); i += 4 {
		val := binary.LittleEndian.Uint32(inst[i:]) ^ key
		binary.LittleEndian.PutUint32(inst[i:], val)
	}
	return inst
}

func (e *Encoder) miniXOR64(inst []byte, key uint64) []byte {
	// ensure the instructions length can be divisible by 8.
	inst = bytes.Clone(inst)
	numPad := len(inst) % 8
	if numPad != 0 {
		numPad = 8 - numPad
	}
	inst = append(inst, e.randBytes(numPad)...)
	for i := 0; i < len(inst); i += 8 {
		val := binary.LittleEndian.Uint64(inst[i:]) ^ key
		binary.LittleEndian.PutUint64(inst[i:], val)
	}
	return inst
}

func (e *Encoder) xsrl(inst []byte, seed, key uint32) []byte {
	// ensure the instructions length can be divisible by 4.
	inst = bytes.Clone(inst)
	numPad := len(inst) % 4
	if numPad != 0 {
		numPad = 4 - numPad
	}
	inst = append(inst, e.randBytes(numPad)...)
	for i := 0; i < len(inst); i += 4 {
		val := binary.LittleEndian.Uint32(inst[i:])
		switch e.arch {
		case 32:
			val ^= key
			val = ror32(val, 17)
			val ^= seed
			val = rol32(val, 5)
		case 64:
			val ^= key
			val = ror32(val, 7)
			val ^= seed
			val = rol32(val, 17)
		}
		binary.LittleEndian.PutUint32(inst[i:], val)
		seed = xorShift32(seed)
	}
	return inst
}

// #nosec G115
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

// #nosec G115
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

func ror32(value uint32, bits uint8) uint32 {
	return value>>bits | value<<(32-bits)
}

func rol32(value uint32, bits uint8) uint32 {
	return value<<bits | value>>(32-bits)
}
