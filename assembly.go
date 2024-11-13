package ssce

import (
	"encoding/hex"
	"fmt"
	"strings"
)

var x64asm = `
.code64

entry:
  {{db .JumpShort}}                          // jump short
  {{db .SaveContext}}                        // save context
  mov rbp, rsp                     {{igi}}   // create new stack frame
  and rsp, 0xFFFFFFFFFFFFFFF0      {{igi}}   // ensure stack is 16 bytes aligned
  
  {{igi}}      {{igi}}
  call calc_entry_addr
  flag_CEA:
  {{igi}}      {{igi}}

  call decrypt_shellcode           {{igi}}

  sub rsp, 0x80                    {{igi}}
  call shellcode_stub              {{igi}}
  add rsp, 0x80                    {{igi}}

  mov rsp, rbp                     {{igi}}   // restore stack
  {{db .RestoreContext}}                     // restore context
  ret                              {{igi}}
  
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

cleaner_stub:
  {{db .CleanerStub}}              {{igi}}

crypto_key:
  {{db .CryptoKey}}                {{igi}}

shellcode_stub:
  {{db .Shellcode}}                {{igi}}
`

type asmContext struct {
	JumpShort      []byte
	SaveContext    []byte
	RestoreContext []byte
	DecryptorStub  []byte
	CleanerStub    []byte
	CryptoKey      []byte
	CryptoKeyLen   int
	Shellcode      []byte
	ShellcodeLen   int
}

func toDB(b []byte) string {
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
