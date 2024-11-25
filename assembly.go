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

  mov {{.EAX}}, {{hex .Seed}}                  {{igi}}
  mov {{.EBX}}, {{hex .Key}}                   {{igi}}

  // prevent continuous 0x00
  mov {{.ECX}}, {{hex .NumLoopStub}}           {{igi}}
  xor {{.ECX}}, {{hex .NumLoopMaskA}}          {{igi}}
  xor {{.ECX}}, {{hex .NumLoopMaskB}}          {{igi}}

  // for prevent "E8 00 00 00 00"
  call calc_body_addr
 flag_CEA:                                          {{igi}}
  add {{.ESI}}, body - flag_CEA + {{hex .OffsetT}}  {{igi}}
  add {{.ESI}}, {{hex .OffsetA}}                    {{igi}}
  sub {{.ESI}}, {{hex .OffsetS}}                    {{igi}}

 loop_xor:
  // xor block data
  mov {{.EDI}}, [{{.ESI}}]                     {{igi}}
  ror {{.EDI}}, 5                              {{igi}}
  xor {{.EDI}}, {{.EAX}}                       {{igi}}
  rol {{.EDI}}, 17                             {{igi}}
  xor {{.EDI}}, {{.EBX}}                       {{igi}}
  mov [{{.ESI}}], {{.EDI}}                     {{igi}}

  // xor shift 32
  // seed ^= seed << 13
  // seed ^= seed >> 17
  // seed ^= seed << 5
  mov {{.EDX}}, {{.EAX}}                       {{igi}}
  shl {{.EDX}}, 13                             {{igi}}
  xor {{.EAX}}, {{.EDX}}                       {{igi}}
  mov {{.EDX}}, {{.EAX}}                       {{igi}}
  shr {{.EDX}}, 17                             {{igi}}
  xor {{.EAX}}, {{.EDX}}                       {{igi}}
  mov {{.EDX}}, {{.EAX}}                       {{igi}}
  shl {{.EDX}}, 5                              {{igi}}
  xor {{.EAX}}, {{.EDX}}                       {{igi}}

  // update address and counter
  add {{.ESI}}, 4                              {{igi}}
  dec {{.ECX}}                                 {{igi}}
  jnz loop_xor                                 {{igi}}

  // restore context
  popfd                                        {{igi}}
  popad                                        {{igi}}

  // go to the shellcode body
  jmp body                                     {{igi}}
calc_body_addr:
  pop  {{.ESI}}                                {{igi}}
  push {{.ESI}}                                {{igi}}
  ret                                          {{igi}}

body:
`

var x64MiniDecoder = `
.code64

// NOT use R register for prevent appear
// a lot of instruction prefix about 0x48

// eax store the random seed
// ebx store the crypto key
// ecx store the loop times
// edx store the xor shift median
// rsi store the body address
// edi store the current value

header:
  push rax                                     {{igi}}
  push rbx                                     {{igi}}
  push rcx                                     {{igi}}
  push rdx                                     {{igi}}
  push rsi                                     {{igi}}
  push rdi                                     {{igi}}
  pushfq                                       {{igi}}

  mov eax, {{hex .Seed}}                       {{igi}}
  mov ebx, {{hex .Key}}                        {{igi}}

  // prevent continuous 0x00
  mov ecx, {{hex .NumLoopStub}}                {{igi}}
  xor ecx, {{hex .NumLoopMaskA}}               {{igi}}
  xor ecx, {{hex .NumLoopMaskB}}               {{igi}}

  // calculate the body address
  lea rsi, [rip + body + {{hex .OffsetT}}]     {{igi}}
  add rsi, {{hex .OffsetA}}                    {{igi}}
  sub rsi, {{hex .OffsetS}}                    {{igi}}

 loop_xor:
  // xor block data
  mov edi, [rsi]                               {{igi}}
  ror edi, 17                                  {{igi}}
  xor edi, eax                                 {{igi}}
  rol edi, 7                                   {{igi}}
  xor edi, ebx                                 {{igi}}
  mov [rsi], edi                               {{igi}}

  // xor shift 32
  // seed ^= seed << 13
  // seed ^= seed >> 17
  // seed ^= seed << 5
  mov edx, eax                                 {{igi}}
  shl edx, 13                                  {{igi}}
  xor eax, edx                                 {{igi}}
  mov edx, eax                                 {{igi}}
  shr edx, 17                                  {{igi}}
  xor eax, edx                                 {{igi}}
  mov edx, eax                                 {{igi}}
  shl edx, 5                                   {{igi}}
  xor eax, edx                                 {{igi}}

  // update address and counter
  add rsi, 4                                   {{igi}}
  dec ecx                                      {{igi}}
  jnz loop_xor                                 {{igi}}

  popfq                                        {{igi}}
  pop rdi                                      {{igi}}
  pop rsi                                      {{igi}}
  pop rdx                                      {{igi}}
  pop rcx                                      {{igi}}
  pop rbx                                      {{igi}}
  pop rax                                      {{igi}}

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

	// for replacement
	EAX string
	EBX string
	ECX string
	EDX string
	ESI string
	EDI string
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
  mov r8, {{hex .DecoderSK}}                 {{igi}}
  call mini_xor                              {{igi}}

  lea rcx, [rbx + eraser_stub]               {{igi}}
  mov rdx, crypto_key_stub - eraser_stub     {{igi}}
  mov r8, {{hex .EraserSK}}                  {{igi}}
  call mini_xor                              {{igi}}

  lea rcx, [rbx + crypto_key_stub]           {{igi}}
  mov rdx, shellcode_stub - crypto_key_stub  {{igi}}
  mov r8, {{hex .CryptoKeySK}}               {{igi}}
  call mini_xor                              {{igi}}
  ret                                        {{igi}}

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

type loaderCtx struct {
	JumpShort      []byte
	SaveContext    []byte
	RestoreContext []byte

	SaveRegister    []byte
	RestoreRegister []byte

	DecoderSK   interface{}
	EraserSK    interface{}
	CryptoKeySK interface{}

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
