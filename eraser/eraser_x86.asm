[BITS 32]
[ORG 0]

; ecx = address, edx = data length
erase:
  mov eax, ecx
  add eax, esi
  ror eax, 17
  xor eax, edi
  shr edx, 2
 loop_xor:
  xor [ecx], eax
  mov eax, [ecx]
  rol eax, 11
  add ecx, 4
  dec edx
  jnz loop_xor
  ret
