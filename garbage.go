package ssce

func (e *Encoder) genGarbageInst() []byte {
	switch e.rand.Intn(1) {
	case 0:
		return nil
	case 1:
		return e.genGarbageJumpShort(16)
	default:
		panic("invalid garbage instruction selection")
	}
}

// jmp short [4-128)
func (e *Encoder) genGarbageJumpShort(max int) []byte {
	if max > 127 || max < 16 {
		panic("max length out of range")
	}
	jmp := make([]byte, 0, 130)
	offset := 4 + e.rand.Intn(max-4)
	jmp = append(jmp, 0xEB, byte(offset))
	// padding garbage data
	inst := e.randBytes(offset)
	jmp = append(jmp, inst...)
	return jmp
}

func (e *Encoder) randBytes(n int) []byte {
	buf := make([]byte, n)
	_, _ = e.rand.Read(buf)
	return buf
}
