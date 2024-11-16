[BITS 64]
[ORG 0]

; rcx = address, rdx = data length
erase:
  mov rdi, rcx       ; load destination address to rdi
  mov rcx, rdx       ; set the counter to the data length
  xor rax, rax       ; clear the rax
  rep stosb          ; fill [rdi] with the value of al, repeat rcx times
  ret                ; return to the caller
