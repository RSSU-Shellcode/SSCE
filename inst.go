package ssce

func (e *Encoder) genGarbageInst() []byte {
	switch e.rand.Intn(1) {
	case 0:
		return e.genGarbageJumpShort()
	case 1:
	}
	return nil
}

// jmp short [4-128)
func (e *Encoder) genGarbageJumpShort() []byte {
	jmp := make([]byte, 0, 130)
	offset := 16 + e.rand.Intn(112)
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
