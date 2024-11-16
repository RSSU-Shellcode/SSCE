package ssce

import (
	"encoding/binary"
)

func (e *Encoder) decoderBuilder() []byte {
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

func (e *Encoder) eraserBuilder() []byte {
	var eraser []byte
	switch e.arch {
	case 32:
		eraser = x86Eraser
	case 64:
		eraser = x64Eraser
	}
	builder := make([]byte, 0, 512)
	builder = append(builder, eraser...)
	return builder
}

func (e *Encoder) cryptoKeyBuilder() []byte {
	builder := make([]byte, 0, 512)
	builder = append(builder, e.key...)
	return builder
}

func (e *Encoder) shellcodeBuilder() []byte {
	builder := make([]byte, 0, 512)
	builder = append(builder, e.sc...)
	return builder
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
