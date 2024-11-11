package ssce

var (
	x86Decoder = []byte{
		0x00,
	}

	x64Decoder = []byte{
		0x48, 0x89, 0x5C, 0x24, 0x08, //      mov qword ptr ss:[rsp+8],rbx
		0x45, 0x33, 0xD2, //                  xor r10d,r10d
		0x4C, 0x8B, 0xD9, //                  mov r11,rcx
		0xB3, 0xFF, //                        mov bl,FF
		0x85, 0xD2, //                        test edx,edx
		0x74, 0x27, //                        je decoder.7FF67A5310B8
		0x8B, 0xD2, //                        mov edx,edx
		0x41, 0x8A, 0x0B, //                  mov cl,byte ptr ds:[r11]
		0x41, 0x8D, 0x42, 0x01, //            lea eax,qword ptr ds:[r10+1]
		0x43, 0x32, 0x0C, 0x02, //            xor cl,byte ptr ds:[r10+r8]
		0x32, 0xCB, //                        xor cl,bl
		0x41, 0x8A, 0x1B, //                  mov bl,byte ptr ds:[r11]
		0x41, 0x88, 0x0B, //                  mov byte ptr ds:[r11],cl
		0x49, 0xFF, 0xC3, //                  inc r11
		0x41, 0x3B, 0xC1, //                  cmp eax,r9d
		0x45, 0x1B, 0xD2, //                  sbb r10d,r10d
		0x44, 0x23, 0xD0, //                  and r10d,eax
		0x48, 0x83, 0xEA, 0x01, //            sub rdx,1
		0x75, 0xDB, //                        jne decoder.7FF67A531093
		0x48, 0x8B, 0x5C, 0x24, 0x08, //      mov rbx,qword ptr ss:[rsp+8]
		0xC3, //                              ret
	}
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

func (e *Encoder) genDecoderCleaner() []byte {
	builder := make([]byte, 0, 64)
	return builder
}

func encryptShellcode(sc, key []byte) {
	last := byte(0xFF)
	var keyIdx = 0
	for i := 0; i < len(sc); i++ {
		b := sc[i] ^ last
		b ^= key[keyIdx]
		sc[i] = b
		last = b
		// update key index
		keyIdx++
		if keyIdx >= len(key) {
			keyIdx = 0
		}
	}
}
