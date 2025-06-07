package ssce

import (
	"embed"
)

// just for prevent [import _ "embed"] :)
var _ embed.FS

// extract functions from decoder.c
var (
	decoderX86 = []byte{
		0x55,       //                                   push ebp
		0x8B, 0xEC, //                                   mov ebp,esp
		0x83, 0xEC, 0x0C, //                             sub esp,C
		0x53,             //                             push ebx
		0x56,             //                             push esi
		0x8B, 0x75, 0x08, //                             mov esi,dword ptr ss:[ebp+8]
		0x57,       //                                   push edi
		0x8B, 0xFA, //                                   mov edi,edx
		0x89, 0x4D, 0xFC, //                             mov dword ptr ss:[ebp-4],ecx
		0x33, 0xD2, //                                   xor edx,edx
		0x8B, 0x1E, //                                   mov ebx,dword ptr ds:[esi]
		0x8B, 0xC3, //                                   mov eax,ebx
		0xF7, 0x75, 0x0C, //                             div dword ptr ss:[ebp+C]
		0x89, 0x5D, 0x08, //                             mov dword ptr ss:[ebp+8],ebx
		0x89, 0x55, 0xF4, //                             mov dword ptr ss:[ebp-C],edx
		0x85, 0xFF, //                                   test edi,edi
		0x74, 0x7A, //                                   je decoder.8E10F4
		0x8B, 0x46, 0x04, //                             mov eax,dword ptr ds:[esi+4]
		0x89, 0x45, 0xF8, //                             mov dword ptr ss:[ebp-8],eax
		0x8A, 0x01, //                                   mov al,byte ptr ds:[ecx]
		0x8A, 0xE3, //                                   mov ah,bl
		0x80, 0xE4, 0x07, //                             and ah,7
		0x8A, 0xD8, //                                   mov bl,al
		0x0F, 0xB6, 0xD4, //                             movzx edx,ah
		0xB1, 0x08, //                                   mov cl,8
		0x2A, 0xCC, //                                   sub cl,ah
		0xD2, 0xEB, //                                   shr bl,cl
		0x8B, 0xCA, //                                   mov ecx,edx
		0xD2, 0xE0, //                                   shl al,cl
		0x8B, 0x4D, 0xF4, //                             mov ecx,dword ptr ss:[ebp-C]
		0x0A, 0xD8, //                                   or bl,al
		0x8A, 0x45, 0xF8, //                             mov al,byte ptr ss:[ebp-8]
		0x32, 0x45, 0x08, //                             xor al,byte ptr ss:[ebp+8]
		0x2A, 0xD8, //                                   sub bl,al
		0x32, 0x1C, 0x31, //                             xor bl,byte ptr ds:[ecx+esi]
		0x8A, 0xC3, //                                   mov al,bl
		0x6A, 0x08, //                                   push 8
		0x59,       //                                   pop ecx
		0x2B, 0xCA, //                                   sub ecx,edx
		0x8B, 0x55, 0xF4, //                             mov edx,dword ptr ss:[ebp-C]
		0xD2, 0xE0, //                                   shl al,cl
		0x42,       //                                   inc edx
		0x8A, 0xCC, //                                   mov cl,ah
		0xD2, 0xEB, //                                   shr bl,cl
		0x8B, 0x4D, 0xFC, //                             mov ecx,dword ptr ss:[ebp-4]
		0x0A, 0xC3, //                                   or al,bl
		0x8B, 0x5D, 0x08, //                             mov ebx,dword ptr ss:[ebp+8]
		0x32, 0xC3, //                                   xor al,bl
		0x88, 0x01, //                                   mov byte ptr ds:[ecx],al
		0x8B, 0xCB, //                                   mov ecx,ebx
		0xC1, 0xE1, 0x0D, //                             shl ecx,D
		0x33, 0xCB, //                                   xor ecx,ebx
		0x8B, 0xC1, //                                   mov eax,ecx
		0xC1, 0xE8, 0x11, //                             shr eax,11
		0x33, 0xC8, //                                   xor ecx,eax
		0x8B, 0xD9, //                                   mov ebx,ecx
		0xC1, 0xE3, 0x05, //                             shl ebx,5
		0x33, 0xD9, //                                   xor ebx,ecx
		0x8B, 0x4D, 0xFC, //                             mov ecx,dword ptr ss:[ebp-4]
		0x41,             //                             inc ecx
		0x89, 0x5D, 0x08, //                             mov dword ptr ss:[ebp+8],ebx
		0xFF, 0x45, 0xF8, //                             inc dword ptr ss:[ebp-8]
		0x3B, 0x55, 0x0C, //                             cmp edx,dword ptr ss:[ebp+C]
		0x89, 0x4D, 0xFC, //                             mov dword ptr ss:[ebp-4],ecx
		0x1B, 0xC0, //                                   sbb eax,eax
		0x23, 0xC2, //                                   and eax,edx
		0x89, 0x45, 0xF4, //                             mov dword ptr ss:[ebp-C],eax
		0x83, 0xEF, 0x01, //                             sub edi,1
		0x75, 0x8C, //                                   jne decoder.8E1080
		0x5F,             //                             pop edi
		0x5E,             //                             pop esi
		0x5B,             //                             pop ebx
		0xC9,             //                             leave
		0xC2, 0x08, 0x00, //                             ret 8
	}

	decoderX64 = []byte{
		0x48, 0x8B, 0xC4, //                             mov rax,rsp
		0x48, 0x89, 0x58, 0x08, //                       mov qword ptr ds:[rax+8],rbx
		0x48, 0x89, 0x68, 0x10, //                       mov qword ptr ds:[rax+10],rbp
		0x48, 0x89, 0x70, 0x18, //                       mov qword ptr ds:[rax+18],rsi
		0x48, 0x89, 0x78, 0x20, //                       mov qword ptr ds:[rax+20],rdi
		0x41, 0x56, //                                   push r14
		0x4D, 0x8B, 0x18, //                             mov r11,qword ptr ds:[r8]
		0x48, 0x8B, 0xDA, //                             mov rbx,rdx
		0x33, 0xD2, //                                   xor edx,edx
		0x49, 0x8B, 0xC3, //                             mov rax,r11
		0x49, 0xF7, 0xF1, //                             div r9
		0x49, 0x8B, 0xF9, //                             mov rdi,r9
		0x4D, 0x8B, 0xD0, //                             mov r10,r8
		0x48, 0x8B, 0xEA, //                             mov rbp,rdx
		0x4C, 0x8B, 0xF1, //                             mov r14,rcx
		0x48, 0x85, 0xDB, //                             test rbx,rbx
		0x0F, 0x84, 0x8A, 0x00, 0x00, 0x00, //           je decoder.7FF742AA112E
		0x49, 0x8B, 0x70, 0x08, //                       mov rsi,qword ptr ds:[r8+8]
		0x41, 0x8A, 0x06, //                             mov al,byte ptr ds:[r14]
		0x45, 0x8A, 0xCB, //                             mov r9b,r11b
		0x44, 0x8A, 0xC0, //                             mov r8b,al
		0x41, 0x80, 0xE1, 0x07, //                       and r9b,7
		0xB9, 0x08, 0x00, 0x00, 0x00, //                 mov ecx,8
		0x41, 0x0F, 0xB6, 0xD1, //                       movzx edx,r9b
		0x41, 0x2A, 0xC9, //                             sub cl,r9b
		0x41, 0xD2, 0xE8, //                             shr r8b,cl
		0x8B, 0xCA, //                                   mov ecx,edx
		0xD2, 0xE0, //                                   shl al,cl
		0xB9, 0x08, 0x00, 0x00, 0x00, //                 mov ecx,8
		0x44, 0x0A, 0xC0, //                             or r8b,al
		0x2B, 0xCA, //                                   sub ecx,edx
		0x40, 0x8A, 0xC6, //                             mov al,sil
		0x48, 0x8D, 0x55, 0x01, //                       lea rdx,qword ptr ss:[rbp+1]
		0x41, 0x32, 0xC3, //                             xor al,r11b
		0x48, 0xFF, 0xC6, //                             inc rsi
		0x44, 0x2A, 0xC0, //                             sub r8b,al
		0x45, 0x32, 0x04, 0x2A, //                       xor r8b,byte ptr ds:[r10+rbp]
		0x41, 0x8A, 0xC0, //                             mov al,r8b
		0xD2, 0xE0, //                                   shl al,cl
		0x41, 0x8A, 0xC9, //                             mov cl,r9b
		0x41, 0xD2, 0xE8, //                             shr r8b,cl
		0x49, 0x8B, 0xCB, //                             mov rcx,r11
		0x41, 0x0A, 0xC0, //                             or al,r8b
		0x48, 0xC1, 0xE1, 0x0D, //                       shl rcx,D
		0x41, 0x32, 0xC3, //                             xor al,r11b
		0x49, 0x33, 0xCB, //                             xor rcx,r11
		0x41, 0x88, 0x06, //                             mov byte ptr ds:[r14],al
		0x48, 0x8B, 0xC1, //                             mov rax,rcx
		0x48, 0xC1, 0xE8, 0x07, //                       shr rax,7
		0x49, 0xFF, 0xC6, //                             inc r14
		0x48, 0x33, 0xC8, //                             xor rcx,rax
		0x4C, 0x8B, 0xD9, //                             mov r11,rcx
		0x49, 0xC1, 0xE3, 0x11, //                       shl r11,11
		0x4C, 0x33, 0xD9, //                             xor r11,rcx
		0x48, 0x3B, 0xD7, //                             cmp rdx,rdi
		0x48, 0x1B, 0xED, //                             sbb rbp,rbp
		0x48, 0x23, 0xEA, //                             and rbp,rdx
		0x48, 0x83, 0xEB, 0x01, //                       sub rbx,1
		0x0F, 0x85, 0x7A, 0xFF, 0xFF, 0xFF, //           jne decoder.7FF742AA10A8
		0x48, 0x8B, 0x5C, 0x24, 0x10, //                 mov rbx,qword ptr ss:[rsp+10]
		0x48, 0x8B, 0x6C, 0x24, 0x18, //                 mov rbp,qword ptr ss:[rsp+18]
		0x48, 0x8B, 0x74, 0x24, 0x20, //                 mov rsi,qword ptr ss:[rsp+20]
		0x48, 0x8B, 0x7C, 0x24, 0x28, //                 mov rdi,qword ptr ss:[rsp+28]
		0x41, 0x5E, //                                   pop r14
		0xC3, //                                         ret
	}
)

var (
	//go:embed eraser/eraser_x86.bin
	eraserX86 []byte

	//go:embed eraser/eraser_x64.bin
	eraserX64 []byte
)
