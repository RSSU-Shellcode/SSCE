package ssce

import (
	"encoding/binary"
)

func (e *Encoder) genDecoderBuilder() []byte {
	var decoder []byte
	switch e.arch {
	case 32:
		decoder = x86Decoder
	case 64:
		decoder = x64Decoder
	}
	builder := make([]byte, 0, 512)
	builder = append(builder, decoder...)
	return builder
}

func (e *Encoder) genCleanBuilder() []byte {
	builder := make([]byte, 0, 64)
	return builder
}

func (e *Encoder) genDecoderStub() []byte {
	var decoder []byte
	switch e.arch {
	case 32:
		decoder = x86Decoder
	case 64:
		decoder = x64Decoder
	}
	return e.randBytes(len(decoder))
}

func (e *Encoder) genCleanerStub() []byte {
	var cleaner []byte
	switch e.arch {
	case 32:
		cleaner = x86Cleaner
	case 64:
		cleaner = x64Cleaner
	}
	return e.randBytes(len(cleaner))
}

func encrypt(data, key []byte) []byte {
	output := make([]byte, len(data))
	ctr := binary.LittleEndian.Uint32(key[4:])
	last := binary.LittleEndian.Uint32(key[:4])
	keyIdx := last % 32
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
		if keyIdx >= uint32(len(key)) {
			keyIdx = 0
		}
		ctr++
		last = xorShift32(last)
	}
	return output
}

func xorShift32(seed uint32) uint32 {
	seed ^= seed << 13
	seed ^= seed >> 17
	seed ^= seed << 5
	return seed
}

func ror(value byte, bits uint8) byte {
	return value>>bits | value<<(8-bits)
}

func rol(value byte, bits uint8) byte {
	return value<<bits | value>>(8-bits)
}
