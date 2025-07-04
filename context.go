package ssce

var (
	saveContextX86    = [][]byte{{0x60}, {0x9C}} // pushad, pushfd
	restoreContextX86 = [][]byte{{0x61}, {0x9D}} // popad, popfd

	saveContextX64 = [][]byte{
		{0x50}, {0x53}, {0x51}, {0x52}, //    push rax, rbx, rcx, rdx
		{0x56}, {0x57}, {0x55}, {0x54}, //    push rsi, rdi, rbp, rsp
		{0x41, 0x50}, {0x41, 0x51}, //        push r8, r9
		{0x41, 0x52}, {0x41, 0x53}, //        push r10, r11
		{0x41, 0x54}, {0x41, 0x55}, //        push r12, r13
		{0x41, 0x56}, {0x41, 0x57}, //        push r14, r15
		{0x9C}, //                            pushfq

	}
	restoreContextX64 = [][]byte{
		{0x58}, {0x5B}, {0x59}, {0x5A}, //    pop rax, rbx, rcx, rdx
		{0x5E}, {0x5F}, {0x5D}, {0x5C}, //    pop rsi, rdi, rbp, rsp
		{0x41, 0x58}, {0x41, 0x59}, //        pop r8, r9
		{0x41, 0x5A}, {0x41, 0x5B}, //        pop r10, r11
		{0x41, 0x5C}, {0x41, 0x5D}, //        pop r12, r13
		{0x41, 0x5E}, {0x41, 0x5F}, //        pop r14, r15
		{0x9D}, //                            popfq
	}
)

func (e *Encoder) saveContext() []byte {
	var save [][]byte
	switch e.arch {
	case 32:
		save = saveContextX86
	case 64:
		save = saveContextX64
	}
	e.contextSeq = e.rand.Perm(len(save))
	inst := make([]byte, 0, 256)
	for i := 0; i < len(save); i++ {
		inst = append(inst, save[e.contextSeq[i]]...)
		inst = append(inst, e.garbageInst()...)
	}
	return inst
}

func (e *Encoder) restoreContext() []byte {
	var restore [][]byte
	switch e.arch {
	case 32:
		restore = restoreContextX86
	case 64:
		restore = restoreContextX64
	}
	inst := make([]byte, 0, 256)
	for i := len(restore) - 1; i >= 0; i-- {
		inst = append(inst, restore[e.contextSeq[i]]...)
		inst = append(inst, e.garbageInst()...)
	}
	return inst
}
