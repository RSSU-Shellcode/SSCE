[BITS 32]
[ORG 0]

; ecx = address, edx = data length
erase:
  mov eax, ecx
  ror eax, 13
  shr edx, 2
  loop_xor:
  xor [ecx], eax
  mov eax, [ecx]
  add ecx, 4
  dec edx
  jnz loop_xor
  ret
