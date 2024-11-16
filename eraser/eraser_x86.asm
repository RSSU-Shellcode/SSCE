[BITS 32]
[ORG 0]

; ecx = address, edx = data length
erase:
  mov edi, ecx       ; load destination address to edi
  mov ecx, edx       ; set the counter to the data length
  xor eax, eax       ; clear the eax
  rep stosb          ; fill [edi] with the value of al, repeat ecx times
  ret                ; return to the caller
