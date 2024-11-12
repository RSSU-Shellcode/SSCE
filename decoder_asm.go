package ssce

// extract functions from decoder.c

var (
	x86Decoder = []byte{
		0x00,
	}

	x64Decoder = []byte{
		0x85, 0xD2, //                              test edx,edx
		0x0F, 0x84, 0xB8, 0x00, 0x00, 0x00, //      je Label1
		0x48, 0x8B, 0xC4, //                        mov rax,rsp
		0x48, 0x89, 0x58, 0x08, //                  mov qword ptr ds:[rax+8],rbx
		0x48, 0x89, 0x68, 0x10, //                  mov qword ptr ds:[rax+10],rbp
		0x48, 0x89, 0x70, 0x18, //                  mov qword ptr ds:[rax+18],rsi
		0x48, 0x89, 0x78, 0x20, //                  mov qword ptr ds:[rax+20],rdi
		0x41, 0x56, //                              push r14
		0x41, 0x8B, 0x18, //                        mov ebx,dword ptr ds:[r8]
		0x45, 0x8B, 0xF1, //                        mov r14d,r9d
		0x41, 0x8B, 0x70, 0x04, //                  mov esi,dword ptr ds:[r8+4]
		0x44, 0x8B, 0xD3, //                        mov r10d,ebx
		0x41, 0x83, 0xE2, 0x1F, //                  and r10d,1F
		0x8B, 0xEA, //                              mov ebp,edx
		0x4D, 0x8B, 0xD8, //                        mov r11,r8
		0x48, 0x8B, 0xF9, //                        mov rdi,rcx
		0x8A, 0x07, //                              [Label2]: mov al,byte ptr ds:[rdi]
		0x44, 0x8A, 0xCB, //                        mov r9b,bl
		0x44, 0x8A, 0xC0, //                        mov r8b,al
		0x41, 0x80, 0xE1, 0x07, //                  and r9b,7
		0x41, 0x0F, 0xB6, 0xD1, //                  movzx edx,r9b
		0xB9, 0x08, 0x00, 0x00, 0x00, //            mov ecx,8
		0x41, 0x2A, 0xC9, //                        sub cl,r9b
		0x41, 0xD2, 0xE8, //                        shr r8b,cl
		0x8B, 0xCA, //                              mov ecx,edx
		0xD2, 0xE0, //                              shl al,cl
		0xB9, 0x08, 0x00, 0x00, 0x00, //            mov ecx,8
		0x44, 0x0A, 0xC0, //                        or r8b,al
		0x2B, 0xCA, //                              sub ecx,edx
		0x40, 0x8A, 0xC6, //                        mov al,sil
		0x41, 0x8D, 0x52, 0x01, //                  lea edx,qword ptr ds:[r10+1]
		0x32, 0xC3, //                              xor al,bl
		0xFF, 0xC6, //                              inc esi
		0x44, 0x2A, 0xC0, //                        sub r8b,al
		0x47, 0x32, 0x04, 0x1A, //                  xor r8b,byte ptr ds:[r10+r11]
		0x41, 0x8A, 0xC0, //                        mov al,r8b
		0xD2, 0xE0, //                              shl al,cl
		0x41, 0x8A, 0xC9, //                        mov cl,r9b
		0x41, 0xD2, 0xE8, //                        shr r8b,cl
		0x8B, 0xCB, //                              mov ecx,ebx
		0x41, 0x0A, 0xC0, //                        or al,r8b
		0xC1, 0xE1, 0x0D, //                        shl ecx,D
		0x32, 0xC3, //                              xor al,bl
		0x33, 0xCB, //                              xor ecx,ebx
		0x88, 0x07, //                              mov byte ptr ds:[rdi],al
		0x8B, 0xC1, //                              mov eax,ecx
		0xC1, 0xE8, 0x11, //                        shr eax,11
		0x48, 0xFF, 0xC7, //                        inc rdi
		0x33, 0xC8, //                              xor ecx,eax
		0x8B, 0xD9, //                              mov ebx,ecx
		0xC1, 0xE3, 0x05, //                        shl ebx,5
		0x33, 0xD9, //                              xor ebx,ecx
		0x41, 0x3B, 0xD6, //                        cmp edx,r14d
		0x45, 0x1B, 0xD2, //                        sbb r10d,r10d
		0x44, 0x23, 0xD2, //                        and r10d,edx
		0x48, 0x83, 0xED, 0x01, //                  sub rbp,1
		0x75, 0x8C, //                              jne Label2
		0x48, 0x8B, 0x5C, 0x24, 0x10, //            mov rbx,qword ptr ss:[rsp+10]
		0x48, 0x8B, 0x6C, 0x24, 0x18, //            mov rbp,qword ptr ss:[rsp+18]
		0x48, 0x8B, 0x74, 0x24, 0x20, //            mov rsi,qword ptr ss:[rsp+20]
		0x48, 0x8B, 0x7C, 0x24, 0x28, //            mov rdi,qword ptr ss:[rsp+28]
		0x41, 0x5E, //                              pop r14
		0xC3, //                                    [Label1]: ret
	}

	x86Cleaner = []byte{
		0x00,
	}

	x64Cleaner = []byte{
		0x00,
	}
)
