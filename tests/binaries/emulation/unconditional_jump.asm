global _start

; This binary is there to test
; emulate vs nearpc/u/pdisas commands
;
; The emulate should show just jump and one nop
; The rest should show jump and two nops

_start:
jmp label
nop
label:
nop
