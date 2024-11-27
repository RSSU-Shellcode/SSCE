package ssce

func (e *Encoder) garbageInst() []byte {
	if e.opts.NoGarbage {
		return nil
	}
	switch e.rand.Intn(2) {
	case 0:
		return nil
	case 1:
		return e.garbageJumpShort(16)
	default:
		panic("invalid garbage instruction selection")
	}
}

func (e *Encoder) garbageInstShort() []byte {
	if e.opts.NoGarbage {
		return nil
	}
	switch e.rand.Intn(1) {
	case 0:
		return e.garbageJumpShort(5)
	default:
		panic("invalid garbage instruction selection")
	}
}

// jmp short [4-128)
func (e *Encoder) garbageJumpShort(max int) []byte {
	if e.opts.NoGarbage {
		return nil
	}
	if max > 127 || max < 3 {
		panic("max length out of range")
	}
	jmp := make([]byte, 0, 1+max)
	offset := 2 + e.rand.Intn(max-2)
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
