package ssce

var (
	saveContextX86    = [][]byte{{0x60}} //              pushad
	restoreContextX86 = [][]byte{{0x61}} //              popad

	saveContextFPX86 = [][]byte{
		{0x9C},                               //         pushfd
		{0x55},                               //         push ebp
		{0x8B, 0xEC},                         //         mov ebp, esp
		{0x81, 0xE4, 0xF0, 0xFF, 0xFF, 0xFF}, //         and esp, 0xFFFFFFF0
		{0x81, 0xEC, 0x00, 0x02, 0x00, 0x00}, //         sub esp, 0x200
		{0x0F, 0xAE, 0x04, 0x24},             //         fxsave [esp]
	}

	restoreContextFPX86 = [][]byte{
		{0x0F, 0xAE, 0x0C, 0x24}, //                     fxrstor [esp]
		{0x8B, 0xE5},             //                     mov esp, ebp
		{0x5D},                   //                     pop ebp
		{0x9D},                   //                     popfd
	}

	saveContextX64 = [][]byte{
		{0x50}, {0x53}, {0x51}, {0x52}, //               push rax, rbx, rcx, rdx
		{0x56}, {0x57}, {0x55}, {0x54}, //               push rsi, rdi, rbp, rsp
		{0x41, 0x50}, {0x41, 0x51}, //                   push r8, r9
		{0x41, 0x52}, {0x41, 0x53}, //                   push r10, r11
		{0x41, 0x54}, {0x41, 0x55}, //                   push r12, r13
		{0x41, 0x56}, {0x41, 0x57}, //                   push r14, r15
	}

	restoreContextX64 = [][]byte{
		{0x58}, {0x5B}, {0x59}, {0x5A}, //               pop rax, rbx, rcx, rdx
		{0x5E}, {0x5F}, {0x5D}, {0x5C}, //               pop rsi, rdi, rbp, rsp
		{0x41, 0x58}, {0x41, 0x59}, //                   pop r8, r9
		{0x41, 0x5A}, {0x41, 0x5B}, //                   pop r10, r11
		{0x41, 0x5C}, {0x41, 0x5D}, //                   pop r12, r13
		{0x41, 0x5E}, {0x41, 0x5F}, //                   pop r14, r15
	}

	saveContextFPX64 = [][]byte{
		{0x9C},                   //                     pushfq
		{0x55},                   //                     push rbp
		{0x48, 0x8B, 0xEC},       //                     mov rbp, rsp
		{0x48, 0x83, 0xE4, 0xF0}, //                     and rsp, 0xFFFFFFFFFFFFFFF0
		{0x48, 0x81, 0xEC, 0x00, 0x02, 0x00, 0x00}, //   sub rsp, 0x200
		{0x0F, 0xAE, 0x04, 0x24},                   //   fxsave [rsp]
	}

	restoreContextFPX64 = [][]byte{
		{0x0F, 0xAE, 0x0C, 0x24}, //                     fxrstor [rsp]
		{0x48, 0x8B, 0xE5},       //                     mov rsp, rbp
		{0x5D},                   //                     pop rbp
		{0x9D},                   //                     popfq
	}
)

func (e *Encoder) saveContext() []byte {
	var (
		save [][]byte
		fp   [][]byte
	)
	switch e.arch {
	case 32:
		save = saveContextX86
		fp = saveContextFPX86
	case 64:
		save = saveContextX64
		fp = saveContextFPX64
	}
	e.contextSeq = e.rand.Perm(len(save))
	inst := make([]byte, 0, 128)
	for i := 0; i < len(fp); i++ {
		inst = append(inst, fp[i]...)
		inst = append(inst, e.garbageInst()...)
	}
	for i := 0; i < len(save); i++ {
		inst = append(inst, save[e.contextSeq[i]]...)
		inst = append(inst, e.garbageInst()...)
	}
	return inst
}

func (e *Encoder) restoreContext() []byte {
	var (
		restore [][]byte
		fp      [][]byte
	)
	switch e.arch {
	case 32:
		restore = restoreContextX86
		fp = restoreContextFPX86
	case 64:
		restore = restoreContextX64
		fp = restoreContextFPX64
	}
	inst := make([]byte, 0, 128)
	for i := len(restore) - 1; i >= 0; i-- {
		inst = append(inst, restore[e.contextSeq[i]]...)
		inst = append(inst, e.garbageInst()...)
	}
	for i := 0; i < len(fp); i++ {
		inst = append(inst, fp[i]...)
		inst = append(inst, e.garbageInst()...)
	}
	return inst
}
