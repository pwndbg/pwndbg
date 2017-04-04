# pwndbg

Pwndbg has a great deal of useful features.  You can a list of all available commands at any time by typing the `pwndbg` command.  Here's a small subset which are easy to capture in screenshots.

## Arguments

All function call sites are annotated with the arguments to those functions.  This works best with debugging symbols, but also works in the most common case where an imported function (e.g. libc function via GOT or PLT) is used.

![](caps/arguments_getenv.png)  
![](caps/arguments_memcpy.png)  
![](caps/arguments_sigsetjmp.png)  
![](caps/arguments_strcpy.png)  
![](caps/arguments_syscall.png)  
![](caps/arguments_xtrace_init.png)  

## Context

A useful summary of the current execution context is printed every time GDB stops (e.g. breakpoint or single-step), displaying all registers, the stack, call frames, disassembly, and additionally recursively dereferencing all pointers.  All memory addresses are color-coded to the type of memory they represent.

![](caps/context.png)  

## Disassembly

Pwndbg uses Capstone Engine to display disassembled instructions, but also leverages its introspection into the instruction to extract memory targets and condition codes.

All absolute jumps are folded away, only displaying relevant instructions.

![](caps/disasm_taken_folded.png)  

Additionally, if the current instruction is conditional, Pwndbg displays whether or not it is evaluated with a green check or a red X, and folds away instructions as necessary.

![](caps/disasm_taken_after.png)  
![](caps/disasm_taken_before.png)  
![](caps/disasn_taken_false.png)  

## Emulation

Pwndbg leverages Unicorn Engine in order to only show instructions which will actually be emulated.  At each debugger stop (e.g. breakpoint or single-step) the next few instructions are silently emulated, and only instructions which will actually be executed are displayed.

This is incredibly useful when stepping through jump tables, PLT entries, and even while ROPping!

![](caps/emulate_vs_disasm.png)  
![](caps/emulation_plt.png)  
![](caps/emulation_rop.png)  

## Heap Inspection

Pwndbg enables introspection of the glibc allocator, ptmalloc2, via a handful of introspection functions.

![](caps/heap_arena.png)  
![](caps/heap_mp.png)  
![](caps/heap_bins.png)  
![](caps/heap_fastbins.png)  
![](caps/heap_unsorted.png)  
![](caps/heap_smallbins.png)  
![](caps/heap_largebins.png)  
![](caps/heap_heap.png)  
![](caps/heap_heap2.png)  
![](caps/heap_mallocchunk.png)  
![](caps/heap_topchunk.png)  
![](caps/fake_fast.png)  

## IDA Pro Integration

Pwndbg flips traditional IDA Pro integration on its head.  Rather than sticking code inside of IDA that you need to interact with, by installing a small [XMLRPC server](ida_script.py) inside of IDA, Pwndbg has full access to everything IDA knows.

This allows extraction of comments, decompiled lines of source, breakpoints, and synchronized debugging (single-steps update the cursor in IDA).

![](caps/ida_comments.png)  
![](caps/ida_function.png)  
![](caps/ida_integration.png)  

Since the complete IDA API is exposed, new tools can be built on this functionality to further enhance Pwndbg's usefulness.

You can also connect to Ida Pro XMLRPC server hosted on different machine. In order to achieve it, you need to change:
* Ida Pro XMLRPC server host (in [ida_script](ida_script.py); as by default it binds to localhost)
* The config parameters responsible for connection (see `config` command)

## Configuration, customization

There are two commands to set various options:

* `theme` - to set particular output color/style
![](caps/theme.png)  

* `config` - to set parameters like whether to emulate code near current instruction, ida rpc connection info, hexdump bytes/width (and more)
![](caps/config.png)  

Of course you can generate and put it in `.gdbinit` after pwndbg initialization to keep it persistent between pwngdb sessions.

This can be seen and achieved by `configfile`/`themefile` commands.

## QEMU Compatibility

Pwndbg is designed to work with minimally-implemented or otherwise debugger-hostile implementations of the GDB Serial Protocol.  One such implementation is that used by QEMU User-Mode Emulation (`qemu-user`) which is frequently used by CTF players to execute and debug cross-architecture binaries.

Vanilla GDB, PEDA, and GEF all fail terribly in this scenario.

#### GEF

![](caps/qemu_gef.png)  

#### PEDA

![](caps/qemu_peda.png)  

#### Vanilla GDB

![](caps/qemu_vanilla.png)  

#### Pwndbg

However, Pwndbg works around the limitations of the GDB stub to give you the best debugger environment possible.

![](caps/qemu_pwndbg.png)  

## Process State Inspection

Use the `procinfo` command in order to inspect the current process state, like UID, GID, Groups, SELinux context, and open file descriptors!  Pwndbg works particularly well with remote GDB debugging like with Android phones, which PEDA, GEF, and vanilla GDB choke on.

![](caps/procinfo.png)  

## ROP Gadgets

Pwndbg makes using ROPGadget easy with the actual addresses in the process.

Just use the `rop` command!

![](caps/rop_grep.png)  

## Search

Pwndbg makes searching the target memory space easy, with a complete and easy-to-use interface.  Whether you're searching for bytes, strings, or various sizes of integer values or pointers, it's a simple command away.

![](caps/search.png)  

## Telescope

Inspecting memory dumps is easy with the `telescope` command.  It recursively dereferences a range of memory, letting you see everything at once.  As an added bonus, Pwndbg checks all of the available registers to see if they point into the memory range.

## Virtual Memory Maps

Pwndbg enhances the standard memory map listing, and allows easy searching.

![](caps/vmmap.png)  
![](caps/vmmap2.png)  
![](caps/vmmap_pc.png)  
![](caps/vmmap_register.png)  
![](caps/vmmap_stack.png)  

## Windbg Compatibility

Pwndbg has a complete windbg compatibility layer.  You can `dd`, `dps`, `eq`, and even `eb eip 90` to your heart's content.

![](caps/windbg.png)  
