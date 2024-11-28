[BITS 64]
[ORG 0]

; rcx = address, rdx = data length
erase:
  mov rax, rcx
  ror rax, 17
  shr rdx, 3
 loop_xor:
  xor [rcx], rax
  mov rax, [rcx]
  rol rax, 13
  xor rax, rcx
  add rcx, 8
  dec rdx
  jnz loop_xor
  ret
