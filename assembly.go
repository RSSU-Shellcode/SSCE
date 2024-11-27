package ssce

import (
	"encoding/hex"
	"fmt"
	"strings"
)

// The role of the mini decoder is to eliminate the
// instruction sequence features as much as possible.

var x86MiniDecoder = `
.code32

// the ret and next labels are used to prevent
// "0x00, 0x00, 0x00" and "0xFF, 0xFF, 0xFF"
// about call or jmp instructions

// eax store the random seed
// ebx store the crypto key
// ecx store the loop times
// edx store the xor shift median
// esi store the body address
// edi store the current value

header:
  // save context
  pushad                                       {{igi}}
  pushfd                                       {{igi}}

  mov {{.Reg.eax}}, {{hex .Seed}}              {{igi}}
  mov {{.Reg.ebx}}, {{hex .Key}}               {{igi}}

  // prevent continuous 0x00
  mov {{.Reg.ecx}}, {{hex .NumLoopStub}}       {{igi}}
  xor {{.Reg.ecx}}, {{hex .NumLoopMaskA}}      {{igi}}
  xor {{.Reg.ecx}}, {{hex .NumLoopMaskB}}      {{igi}}

  // for prevent "E8 00 00 00 00"
  call calc_body_addr
 flag_CEA:                                              {{igi}}
  add {{.Reg.esi}}, body - flag_CEA + {{hex .OffsetT}}  {{igi}}
  add {{.Reg.esi}}, {{hex .OffsetA}}                    {{igi}}
  sub {{.Reg.esi}}, {{hex .OffsetS}}                    {{igi}}

  // decode shellcode body
 loop_xor:
  mov {{.Reg.edi}}, [{{.Reg.esi}}]             {{igs}}
  ror {{.Reg.edi}}, 5                          {{igs}}
  xor {{.Reg.edi}}, {{.Reg.eax}}               {{igs}}
  rol {{.Reg.edi}}, 17                         {{igs}}
  xor {{.Reg.edi}}, {{.Reg.ebx}}               {{igs}}
  mov [{{.Reg.esi}}], {{.Reg.edi}}             {{igs}}

  // call xor shift 32
  jmp xor_shift_32                             {{igs}}
 ret_1:

  // update address and counter
  add {{.Reg.esi}}, 4                          {{igs}}
  dec {{.Reg.ecx}}                             {{igs}}
  jnz loop_xor                                 {{igs}}

  // skip function xor shift 32
  jmp next_1                                   {{igs}}

xor_shift_32:
  mov {{.Reg.edx}}, {{.Reg.eax}}               {{igs}}
  shl {{.Reg.edx}}, 13                         {{igs}}
  xor {{.Reg.eax}}, {{.Reg.edx}}               {{igs}}
  mov {{.Reg.edx}}, {{.Reg.eax}}               {{igs}}
  shr {{.Reg.edx}}, 17                         {{igs}}
  xor {{.Reg.eax}}, {{.Reg.edx}}               {{igs}}
  mov {{.Reg.edx}}, {{.Reg.eax}}               {{igs}}
  shl {{.Reg.edx}}, 5                          {{igs}}
  xor {{.Reg.eax}}, {{.Reg.edx}}               {{igs}}
  jmp ret_1                                    {{igs}}
 next_1:

  // restore context
  popfd                                        {{igi}}
  popad                                        {{igi}}

{{if .Padding}}
  {{igi}}  {{igi}}  {{igi}}  {{igi}}
  {{igi}}  {{igi}}  {{igi}}  {{igi}}
  {{igi}}  {{igi}}  {{igi}}  {{igi}}
  {{igi}}  {{igi}}  {{igi}}  {{igi}}
  {{igi}}  {{igi}}  {{igi}}  {{igi}}
  {{igi}}  {{igi}}  {{igi}}  {{igi}}
  {{igi}}  {{igi}}  {{igi}}  {{igi}}
  {{igi}}  {{igi}}  {{igi}}  {{igi}}
{{end}}

  // go to the shellcode body
  jmp body                                     {{igi}}

{{if .Padding}}
  {{db .PadData}}
{{end}}

calc_body_addr:
  pop  {{.Reg.esi}}                            {{igi}}
  push {{.Reg.esi}}                            {{igi}}
  ret                                          {{igi}}

body:
`

var x64MiniDecoder = `
.code64

// NOT use R register for prevent appear
// a lot of instruction prefix about 0x48

// dr is used to get the register low 32bit

// the ret and next labels are used to prevent
// "0x00, 0x00, 0x00" and "0xFF, 0xFF, 0xFF"
// about call or jmp instructions

// eax store the random seed
// ebx store the crypto key
// ecx store the loop times
// edx store the xor shift median
// rsi store the body address
// edi store the current value

header:
  // save context
  push {{.Reg.rax}}                            {{igi}}
  push {{.Reg.rbx}}                            {{igi}}
  push {{.Reg.rcx}}                            {{igi}}
  push {{.Reg.rdx}}                            {{igi}}
  push {{.Reg.rsi}}                            {{igi}}
  push {{.Reg.rdi}}                            {{igi}}
  pushfq                                       {{igi}}

  mov {{dr .Reg.rax}}, {{hex .Seed}}           {{igi}}
  mov {{dr .Reg.rbx}}, {{hex .Key}}            {{igi}}

  // prevent continuous 0x00
  mov {{dr .Reg.rcx}}, {{hex .NumLoopStub}}    {{igi}}
  xor {{dr .Reg.rcx}}, {{hex .NumLoopMaskA}}   {{igi}}
  xor {{dr .Reg.rcx}}, {{hex .NumLoopMaskB}}   {{igi}}

  // calculate the body address
  lea {{.Reg.rsi}}, [rip + body + {{hex .OffsetT}}]   {{igi}}
  add {{.Reg.rsi}}, {{hex .OffsetA}}                  {{igi}}
  sub {{.Reg.rsi}}, {{hex .OffsetS}}                  {{igi}}

  // decode shellcode body
 loop_xor:
  mov {{dr .Reg.rdi}}, [{{.Reg.rsi}}]          {{igs}}
  ror {{dr .Reg.rdi}}, 17                      {{igs}}
  xor {{dr .Reg.rdi}}, {{dr .Reg.rax}}         {{igs}}
  rol {{dr .Reg.rdi}}, 7                       {{igs}}
  xor {{dr .Reg.rdi}}, {{dr .Reg.rbx}}         {{igs}}
  mov [{{.Reg.rsi}}], {{dr .Reg.rdi}}          {{igs}}

  // call xor shift 32
  jmp xor_shift_32                             {{igs}}
 ret_1:

  // update address and counter
  add {{.Reg.rsi}}, 4                          {{igs}}
  dec {{dr .Reg.rcx}}                          {{igs}}
  jnz loop_xor                                 {{igs}}

  // skip function xor shift 32
  jmp next_1                                   {{igs}}

xor_shift_32:
  mov {{dr .Reg.rdx}}, {{dr .Reg.rax}}         {{igs}}
  shl {{dr .Reg.rdx}}, 13                      {{igs}}
  xor {{dr .Reg.rax}}, {{dr .Reg.rdx}}         {{igs}}
  mov {{dr .Reg.rdx}}, {{dr .Reg.rax}}         {{igs}}
  shr {{dr .Reg.rdx}}, 17                      {{igs}}
  xor {{dr .Reg.rax}}, {{dr .Reg.rdx}}         {{igs}}
  mov {{dr .Reg.rdx}}, {{dr .Reg.rax}}         {{igs}}
  shl {{dr .Reg.rdx}}, 5                       {{igs}}
  xor {{dr .Reg.rax}}, {{dr .Reg.rdx}}         {{igs}}
  jmp ret_1                                    {{igs}}
 next_1:

  // restore context
  popfq                                        {{igi}}
  pop {{.Reg.rdi}}                             {{igi}}
  pop {{.Reg.rsi}}                             {{igi}}
  pop {{.Reg.rdx}}                             {{igi}}
  pop {{.Reg.rcx}}                             {{igi}}
  pop {{.Reg.rbx}}                             {{igi}}
  pop {{.Reg.rax}}                             {{igi}}

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

	// for replace registers
	Reg map[string]string

	// for prevent call short
	Padding bool
	PadData []byte
}

// The role of the shellcode loader is to execute the shellcode
// without destroying the CPU context, and to erase the loader
// before execution and the shellcode after execution.

var x86Loader = `
.code32

entry:
  // save context and prepare the environment
  {{db .JumpShort}}                            // random jump short
  {{db .SaveContext}}                          // save GP registers
  push ebx                                     // store ebx for save entry address
  push ebp                                     // store ebp for save stack address
  mov ebp, esp                                 // create new stack frame
  and esp, 0xFFFFFFF0                          // ensure stack is 16 bytes aligned
  sub esp, 0x200                               // reserve stack
  fxsave [esp]                                 // save FP registers

  // calculate the entry address
  call calc_entry_addr
 flag_CEA:

  // save arguments for call shellcode
  push ecx
  push edx
  // push r8
  // push r9

  // decode instructions in stub and erase them
  call decode_stubs
  call decode_shellcode
  call erase_decoder_stub
  call erase_crypto_key_stub

 // erase useless functions and entry
 flag_eraser_1:
  lea ecx, [ebx + mini_xor]          {{igi}}
  mov edx, decoder_stub - mini_xor   {{igi}}
  call eraser_stub                   {{igi}}

  mov ecx, ebx                       {{igi}}
  mov edx, flag_eraser_1             {{igi}}
  call eraser_stub                   {{igi}}

  // restore arguments for call shellcode
  // pop r9                             {{igi}}
  // pop r8                             {{igi}}
  pop edx                            {{igi}}
  pop ecx                            {{igi}}

  // execute the shellcode
  push ebp                                     // store ebp for save stack address
  mov ebp, esp                                 // create new stack frame
  sub esp, 0x40                      {{igi}}   // reserve stack for protect
  call shellcode_stub                {{igi}}   // call the shellcode
  mov esp, ebp                       {{igi}}   // restore stack address
  pop ebp                            {{igi}}   // restore ebp

  // save the shellcode return value
  push eax                           {{igi}}

  // erase the shellcode stub
{{if .EraseShellcode}}
  lea ecx, [ebx + shellcode_stub]    {{igi}}
  mov edx, {{hex .ShellcodeLen}}     {{igi}}
  call eraser_stub                   {{igi}}
{{end}}

  // erase the above instructions
 flag_eraser_2:
  mov ecx, ebx                       {{igi}}
  mov edx, flag_eraser_2             {{igi}}
  call eraser_stub                   {{igi}}

  // erase the eraser stub
  lea edi, [ebx + eraser_stub]       {{igi}}
  lea esi, [ebx + crypto_key_stub]   {{igi}}
  mov ecx, {{hex .EraserLen}}        {{igi}}
  cld                                {{igi}}
  rep movsb                          {{igi}}

  // restore the shellcode return value
  pop eax                            {{igi}}

  fxrstor [esp]                      {{igi}}   // restore FP registers
  add esp, 0x200                     {{igi}}   // reserve stack
  mov esp, ebp                       {{igi}}   // restore stack address
  pop ebp                            {{igi}}   // restore ebp
  pop ebx                            {{igi}}   // restore ebx
  {{db .RestoreContext}}                       // restore GP registers
  ret                                {{igi}}   // return to the caller

calc_entry_addr:
  pop eax                                      // get return address
  mov ebx, eax                                 // calculate entry address
  sub ebx, flag_CEA                            // fix bug for assembler
  push eax                                     // push return address
  ret                                          // return to the entry

// ecx = data address, edx = data length, eax = key.
// this function assumes that the data length is divisible by 4.
mini_xor:
  shr edx, 2     // edx /= 2
  loop_xor:
  xor [ecx], eax
  add ecx, 4
  dec edx
  jnz loop_xor
  ret

decode_stubs:
  mov eax, {{hex .StubKey}}

  lea ecx, [ebx + decoder_stub]
  mov edx, eraser_stub - decoder_stub
  call mini_xor

  lea ecx, [ebx + eraser_stub]
  mov edx, crypto_key_stub - eraser_stub
  call mini_xor

  lea ecx, [ebx + crypto_key_stub]
  mov edx, shellcode_stub - crypto_key_stub
  call mini_xor
  ret

decode_shellcode:
  lea ecx, [ebx + shellcode_stub]
  mov edx, {{hex .ShellcodeLen}}
  mov eax, {{hex .CryptoKeyLen}}
  push eax
  lea eax, [ebx + crypto_key_stub]
  push eax
  call decoder_stub
  ret

erase_decoder_stub:
  lea ecx, [ebx + decoder_stub]
  mov edx, eraser_stub - decoder_stub
  call eraser_stub
  ret

erase_crypto_key_stub:
  lea ecx, [ebx + crypto_key_stub]
  mov edx, shellcode_stub - crypto_key_stub
  call eraser_stub
  ret

decoder_stub:
  {{db .DecoderStub}}                {{igi}}

eraser_stub:
  {{db .EraserStub}}                 {{igi}}

crypto_key_stub:
  {{db .CryptoKeyStub}}              {{igi}}

shellcode_stub:
`

var x64Loader = `
.code64

entry:
  // save context and prepare the environment
  {{db .JumpShort}}                            // random jump short
  {{db .SaveContext}}                          // save GP registers
  push rbx                                     // store rbx for save entry address
  push rbp                                     // store rbp for save stack address
  mov rbp, rsp                                 // create new stack frame
  and rsp, 0xFFFFFFFFFFFFFFF0                  // ensure stack is 16 bytes aligned
  sub rsp, 0x200                               // reserve stack
  fxsave [rsp]                                 // save FP registers

  // calculate the entry address
  lea rbx, [rip + entry]

  // save arguments for call shellcode
  push rcx
  push rdx
  push r8
  push r9

  // decode instructions in stub and erase them
  call decode_stubs
  call decode_shellcode
  call erase_decoder_stub
  call erase_crypto_key_stub

  // erase useless functions and entry
 flag_eraser_1:
  lea rcx, [rbx + mini_xor]          {{igi}}
  mov rdx, decoder_stub - mini_xor   {{igi}}
  call eraser_stub                   {{igi}}

  mov rcx, rbx                       {{igi}}
  mov rdx, flag_eraser_1             {{igi}}
  call eraser_stub                   {{igi}}

  // restore arguments for call shellcode
  pop r9                             {{igi}}
  pop r8                             {{igi}}
  pop rdx                            {{igi}}
  pop rcx                            {{igi}}

  // execute the shellcode
  sub rsp, 0x80                      {{igi}}
  call shellcode_stub                {{igi}}
  add rsp, 0x80                      {{igi}}

  // save the shellcode return value
  push rax                           {{igi}}

  // erase the shellcode stub
{{if .EraseShellcode}}
  lea rcx, [rbx + shellcode_stub]    {{igi}}
  mov rdx, {{hex .ShellcodeLen}}     {{igi}}
  call eraser_stub                   {{igi}}
{{end}}

  // erase the above instructions
 flag_eraser_2:
  mov rcx, rbx                       {{igi}}
  mov rdx, flag_eraser_2             {{igi}}
  call eraser_stub                   {{igi}}

  // erase the eraser stub
  lea rdi, [rbx + eraser_stub]       {{igi}}
  lea rsi, [rbx + crypto_key_stub]   {{igi}}
  mov rcx, {{hex .EraserLen}}        {{igi}}
  cld                                {{igi}}
  rep movsb                          {{igi}}

  // restore the shellcode return value
  pop rax                            {{igi}}

  fxrstor [rsp]                      {{igi}}   // restore FP registers
  add rsp, 0x200                     {{igi}}   // reserve stack
  mov rsp, rbp                       {{igi}}   // restore stack address
  pop rbp                            {{igi}}   // restore rbp
  pop rbx                            {{igi}}   // restore rbx
  {{db .RestoreContext}}                       // restore GP registers
  ret                                {{igi}}   // return to the caller

// rcx = data address, rdx = data length, r8 = key.
// this function assumes that the data length is divisible by 8.
mini_xor:
  shr rdx, 3     // rdx /= 8
  loop_xor:
  xor [rcx], r8
  add rcx, 8
  dec rdx
  jnz loop_xor
  ret

decode_stubs:
  mov r8, {{hex .StubKey}}

  lea rcx, [rbx + decoder_stub]
  mov rdx, eraser_stub - decoder_stub
  call mini_xor

  lea rcx, [rbx + eraser_stub]
  mov rdx, crypto_key_stub - eraser_stub
  call mini_xor

  lea rcx, [rbx + crypto_key_stub]
  mov rdx, shellcode_stub - crypto_key_stub
  call mini_xor
  ret

decode_shellcode:
  lea rcx, [rbx + shellcode_stub]
  mov rdx, {{hex .ShellcodeLen}}
  lea r8, [rbx + crypto_key_stub]
  mov r9, {{hex .CryptoKeyLen}}
  sub rsp, 0x40
  call decoder_stub
  add rsp, 0x40
  ret

erase_decoder_stub:
  lea rcx, [rbx + decoder_stub]
  mov rdx, eraser_stub - decoder_stub
  call eraser_stub
  ret

erase_crypto_key_stub:
  lea rcx, [rbx + crypto_key_stub]
  mov rdx, shellcode_stub - crypto_key_stub
  call eraser_stub
  ret

decoder_stub:
  {{db .DecoderStub}}                {{igi}}

eraser_stub:
  {{db .EraserStub}}                 {{igi}}

crypto_key_stub:
  {{db .CryptoKeyStub}}              {{igi}}

shellcode_stub:
`

type loaderCtx struct {
	JumpShort      []byte
	SaveContext    []byte
	RestoreContext []byte

	StubKey interface{}

	DecoderStub   []byte
	EraserStub    []byte
	CryptoKeyStub []byte

	CryptoKeyLen int
	ShellcodeLen int
	EraserLen    int

	EraseShellcode bool
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
