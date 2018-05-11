global _start

; This binary is there to test
; emulate vs nearpc/u/pdisas commands
;

_start:
mov rax, 0x1337
mov rbx, 0xFFFF
call some_func
nop
call rax

some_func:
  mov rax, rbx
  ret
