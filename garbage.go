package ssce

// the output garbage instruction length is no limit.
func (e *Encoder) garbageInst() []byte {
	if e.opts.NoGarbage {
		return nil
	}
	switch e.rand.Intn(3) {
	case 0:
		return nil
	case 1:
		return e.garbageJumpShort(2, 16)
	case 2:
		return e.garbageMultiByteNOP()
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
	switch e.rand.Intn(6) {
	case 0:
		nop = []byte{0x90}
	case 1:
		nop = []byte{0x66, 0x90}
	case 2:
		nop = []byte{0x0F, 0x1F, 0x00}
	case 3:
		nop = []byte{0x0F, 0x1F, 0x40, 0x00}
	case 4:
		nop = []byte{0x0F, 0x1F, 0x44, 0x00, 0x00}
	case 5:
		nop = []byte{0x66, 0x0F, 0x1F, 0x44, 0x00, 0x00}
	}
	return nop
}

// random add, sub, inc, dec
func (e *Encoder) garbageDestroyFlag() []byte {
	inst := []byte{0x9C} // pushfd/pushfq

	inst = append(inst, 0x9D) // popfd/popfq
	return inst
}
