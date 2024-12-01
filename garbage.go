package ssce

func (e *Encoder) garbageInst() []byte {
	if e.opts.NoGarbage {
		return nil
	}
	switch e.rand.Intn(2) {
	case 0:
		return nil
	case 1:
		return e.garbageJumpShort(2, 16)
	default:
		panic("invalid garbage instruction selection")
	}
}

func (e *Encoder) garbageInstShort() []byte {
	if e.opts.NoGarbage {
		return nil
	}
	switch e.rand.Intn(2) {
	case 0:
		return nil
	case 1:
		return e.garbageJumpShort(2, 5)
	default:
		panic("invalid garbage instruction selection")
	}
}

// jmp short [4-128)
func (e *Encoder) garbageJumpShort(min, max int) []byte {
	if e.opts.NoGarbage {
		return nil
	}
	if min < 1 || max > 127 {
		panic("garbage jump short length out of range")
	}
	jmp := make([]byte, 0, 1+max/2)
	offset := min + e.rand.Intn(max-min+1)
	jmp = append(jmp, 0xEB, byte(offset))
	jmp = append(jmp, e.randBytes(offset)...)
	return jmp
}

func (e *Encoder) randBytes(n int) []byte {
	buf := make([]byte, n)
	_, _ = e.rand.Read(buf)
	return buf
}

func (e *Encoder) randString(n int) []byte {
	buf := make([]byte, n)
	for i := 0; i < n; i++ {
		buf[i] = byte(32 + e.rand.Intn(95)) // [32, 126]
	}
	return buf
}
