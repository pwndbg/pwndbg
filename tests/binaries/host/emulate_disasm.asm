global _start

; This binary is there to test
; emulate vs nearpc/u/pdisas commands
; The emulate should show just jump and one nop
; The rest should show jump and two nops
;
; Motivated by https://github.com/pwndbg/pwndbg/issues/315

_start:
jmp label
nop
label:
nop
