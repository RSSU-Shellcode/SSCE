package main

import (
	"bufio"
	"encoding/hex"
	"fmt"
	"strings"
)

// extract function from x96dbg
var input = `
00007FF748D0106C | 48:8BC4                       | mov rax,rsp
00007FF748D0106F | 48:8958 08                    | mov qword ptr ds:[rax+8],rbx
00007FF748D01073 | 48:8968 10                    | mov qword ptr ds:[rax+10],rbp
00007FF748D01077 | 48:8970 18                    | mov qword ptr ds:[rax+18],rsi
00007FF748D0107B | 48:8978 20                    | mov qword ptr ds:[rax+20],rdi
00007FF748D0107F | 41:56                         | push r14
00007FF748D01081 | 4D:8B18                       | mov r11,qword ptr ds:[r8]
00007FF748D01084 | 48:8BDA                       | mov rbx,rdx
00007FF748D01087 | 33D2                          | xor edx,edx
00007FF748D01089 | 49:8BC3                       | mov rax,r11
00007FF748D0108C | 49:F7F1                       | div r9
00007FF748D0108F | 49:8BF9                       | mov rdi,r9
00007FF748D01092 | 4D:8BD0                       | mov r10,r8
00007FF748D01095 | 48:8BEA                       | mov rbp,rdx
00007FF748D01098 | 4C:8BF1                       | mov r14,rcx
00007FF748D0109B | 48:85DB                       | test rbx,rbx
00007FF748D0109E | 0F84 8A000000                 | je decoder.7FF748D0112E
00007FF748D010A4 | 49:8B70 08                    | mov rsi,qword ptr ds:[r8+8]
00007FF748D010A8 | 41:8A06                       | mov al,byte ptr ds:[r14]
00007FF748D010AB | 45:8ACB                       | mov r9b,r11b
00007FF748D010AE | 44:8AC0                       | mov r8b,al
00007FF748D010B1 | 41:80E1 07                    | and r9b,7
00007FF748D010B5 | B9 08000000                   | mov ecx,8
00007FF748D010BA | 41:0FB6D1                     | movzx edx,r9b
00007FF748D010BE | 41:2AC9                       | sub cl,r9b
00007FF748D010C1 | 41:D2E8                       | shr r8b,cl
00007FF748D010C4 | 8BCA                          | mov ecx,edx
00007FF748D010C6 | D2E0                          | shl al,cl
00007FF748D010C8 | B9 08000000                   | mov ecx,8
00007FF748D010CD | 44:0AC0                       | or r8b,al
00007FF748D010D0 | 2BCA                          | sub ecx,edx
00007FF748D010D2 | 40:8AC6                       | mov al,sil
00007FF748D010D5 | 48:8D55 01                    | lea rdx,qword ptr ss:[rbp+1]
00007FF748D010D9 | 41:32C3                       | xor al,r11b
00007FF748D010DC | 48:FFC6                       | inc rsi
00007FF748D010DF | 44:2AC0                       | sub r8b,al
00007FF748D010E2 | 45:32042A                     | xor r8b,byte ptr ds:[r10+rbp]
00007FF748D010E6 | 41:8AC0                       | mov al,r8b
00007FF748D010E9 | D2E0                          | shl al,cl
00007FF748D010EB | 41:8AC9                       | mov cl,r9b
00007FF748D010EE | 41:D2E8                       | shr r8b,cl
00007FF748D010F1 | 49:8BCB                       | mov rcx,r11
00007FF748D010F4 | 41:0AC0                       | or al,r8b
00007FF748D010F7 | 48:C1E1 0D                    | shl rcx,D
00007FF748D010FB | 41:32C3                       | xor al,r11b
00007FF748D010FE | 49:33CB                       | xor rcx,r11
00007FF748D01101 | 41:8806                       | mov byte ptr ds:[r14],al
00007FF748D01104 | 48:8BC1                       | mov rax,rcx
00007FF748D01107 | 48:C1E8 07                    | shr rax,7
00007FF748D0110B | 49:FFC6                       | inc r14
00007FF748D0110E | 48:33C8                       | xor rcx,rax
00007FF748D01111 | 4C:8BD9                       | mov r11,rcx
00007FF748D01114 | 49:C1E3 11                    | shl r11,11
00007FF748D01118 | 4C:33D9                       | xor r11,rcx
00007FF748D0111B | 48:3BD7                       | cmp rdx,rdi
00007FF748D0111E | 48:1BED                       | sbb rbp,rbp
00007FF748D01121 | 48:23EA                       | and rbp,rdx
00007FF748D01124 | 48:83EB 01                    | sub rbx,1
00007FF748D01128 | 0F85 7AFFFFFF                 | jne decoder.7FF748D010A8
00007FF748D0112E | 48:8B5C24 10                  | mov rbx,qword ptr ss:[rsp+10]
00007FF748D01133 | 48:8B6C24 18                  | mov rbp,qword ptr ss:[rsp+18]
00007FF748D01138 | 48:8B7424 20                  | mov rsi,qword ptr ss:[rsp+20]
00007FF748D0113D | 48:8B7C24 28                  | mov rdi,qword ptr ss:[rsp+28]
00007FF748D01142 | 41:5E                         | pop r14
00007FF748D01144 | C3                            | ret
`

func main() {
	output := new(strings.Builder)
	scanner := bufio.NewScanner(strings.NewReader(input))
	for scanner.Scan() {
		text := scanner.Text()
		if text == "" {
			continue
		}
		set := strings.Split(text, "|")
		inst := set[1]
		asm := set[2]

		inst = strings.ReplaceAll(inst, ":", "")
		inst = strings.ReplaceAll(inst, " ", "")
		b, err := hex.DecodeString(inst)
		if err != nil {
			panic(err)
		}
		for i := 0; i < len(b); i++ {
			_, _ = fmt.Fprintf(output, "0x%02X, ", b[i])
		}

		output.WriteString("//")
		padding := 46 - len(b)*6
		output.WriteString(strings.Repeat(" ", padding))
		output.WriteString(asm)

		output.WriteString("\n")
	}
	fmt.Println(output)
}
