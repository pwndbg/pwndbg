global _start

; This binary is there to test
; emulate vs nearpc/u/pdisas commands

_start:
test rax, rax
jne branch
mov rax, 0x1337

branch:
  nop
