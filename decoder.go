package ssce

import (
	"bytes"
	"encoding/binary"
)

func (e *Encoder) decoderStub() []byte {
	var decoder []byte
	switch e.arch {
	case 32:
		decoder = x86Decoder
	case 64:
		decoder = x64Decoder
	}
	return e.miniXOR(decoder, e.decoderStubKey)
}

func (e *Encoder) eraserStub() []byte {
	var eraser []byte
	switch e.arch {
	case 32:
		eraser = x86Eraser
	case 64:
		eraser = x64Eraser
	}
	return e.miniXOR(eraser, e.eraserStubKey)
}

func (e *Encoder) cryptoKeyStub() []byte {
	return e.miniXOR(e.key, e.cryptoKeyStubKey)
}

func (e *Encoder) miniXOR(inst []byte, key interface{}) []byte {
	switch e.arch {
	case 32:
		return e.miniXOR32(inst, key.(uint32))
	case 64:
		return e.miniXOR64(inst, key.(uint64))
	default:
		panic("invalid architecture")
	}
}

func (e *Encoder) miniXOR32(inst []byte, key uint32) []byte {
	l := len(inst)
	inst = bytes.Clone(inst)
	// ensure the instructions length can be divisible by 4.
	numPad := l % 4
	if numPad != 0 {
		numPad = 4 - numPad
	}
	inst = append(inst, e.randBytes(numPad)...)
	for i := 0; i < len(inst); i += 4 {
		val := binary.LittleEndian.Uint32(inst[i:i+4]) ^ key
		binary.LittleEndian.PutUint32(inst[i:i+4], val)
	}
	return inst
}

func (e *Encoder) miniXOR64(inst []byte, key uint64) []byte {
	l := len(inst)
	inst = bytes.Clone(inst)
	// ensure the instructions length can be divisible by 8.
	numPad := l % 8
	if numPad != 0 {
		numPad = 8 - numPad
	}
	inst = append(inst, e.randBytes(numPad)...)
	seed := e.rand.Uint64()
	for i := 0; i < len(inst); i += 8 {
		val := binary.LittleEndian.Uint64(inst[i : i+8])
		val ^= key
		val = ror64(val, uint8(key%64))
		val ^= seed
		val = rol64(val, uint8(seed%64))
		binary.LittleEndian.PutUint64(inst[i:i+8], val)
		seed = xorShift64(seed)
	}
	return inst
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

func ror64(value uint64, bits uint8) uint64 {
	return value>>bits | value<<(64-bits)
}

func rol64(value uint64, bits uint8) uint64 {
	return value<<bits | value>>(64-bits)
}

func ror(value byte, bits uint8) byte {
	return value>>bits | value<<(8-bits)
}

func rol(value byte, bits uint8) byte {
	return value<<bits | value>>(8-bits)
}
