pwndbg> disassemble tcache_init
Dump of assembler code for function tcache_init:
   0x0000fffff7e9042c <+0>:	paciasp
   0x0000fffff7e90430 <+4>:	stp	x29, x30, [sp, #-32]!
   0x0000fffff7e90434 <+8>:	mov	x0, #0x2f8                 	// #760
   0x0000fffff7e90438 <+12>:	mov	x29, sp
   0x0000fffff7e9043c <+16>:	bl	0xfffff7e90184 <__libc_malloc2>
   0x0000fffff7e90440 <+20>:	adrp	x2, 0xfffff7faf000 <_nl_C_locobj+144>
   0x0000fffff7e90444 <+24>:	ldr	x2, [x2, #3432]
   0x0000fffff7e90448 <+28>:	mrs	x1, tpidr_el0
   0x0000fffff7e9044c <+32>:	add	x1, x1, x2
   0x0000fffff7e90450 <+36>:	str	x0, [x1, #8]
   0x0000fffff7e90454 <+40>:	cbz	x0, 0xfffff7e90494 <tcache_init+104>
   0x0000fffff7e90458 <+44>:	mov	w1, #0x0                   	// #0
   0x0000fffff7e9045c <+48>:	mov	x2, #0x2f8                 	// #760
   0x0000fffff7e90460 <+52>:	str	x0, [sp, #24]
   0x0000fffff7e90464 <+56>:	bl	0xfffff7e9d680 <__memset_generic>
   0x0000fffff7e90468 <+60>:	adrp	x0, 0xfffff7fb0000 <current_rtmin>
   0x0000fffff7e9046c <+64>:	ldr	x3, [sp, #24]
   0x0000fffff7e90470 <+68>:	ldr	h30, [x0, #392]
   0x0000fffff7e90474 <+72>:	mov	x1, x3
   0x0000fffff7e90478 <+76>:	add	x0, x3, #0x90
   0x0000fffff7e9047c <+80>:	dup	v31.4h, v30.h[0]
   0x0000fffff7e90480 <+84>:	dup	v30.8h, v30.h[0]
   0x0000fffff7e90484 <+88>:	str	q30, [x1], #16
   0x0000fffff7e90488 <+92>:	cmp	x1, x0
   0x0000fffff7e9048c <+96>:	b.ne	0xfffff7e90484 <tcache_init+88>  // b.any
   0x0000fffff7e90490 <+100>:	str	d31, [x3, #144]
   0x0000fffff7e90494 <+104>:	ldp	x29, x30, [sp], #32
   0x0000fffff7e90498 <+108>:	autiasp
   0x0000fffff7e9049c <+112>:	ret
End of assembler dump.
