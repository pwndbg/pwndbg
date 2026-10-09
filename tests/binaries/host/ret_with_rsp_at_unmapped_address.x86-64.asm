global _start

_start:

; The high bits being set here check an important edge case in the test.
; When displaying the failed address, do not displayed a masked address.
; Show the entire 64 bits.
mov rsp, 0xffffffffdeadbeef
ret
