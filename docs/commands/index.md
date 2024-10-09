



# Commands

## Start

-  [attachp](attachp/attachp.md) Attaches to a given pid, process name or device file.
-  [entry](start/entry.md)
-  [sstart](start/sstart.md) Alias for 'tbreak __libc_start_main; run'.
-  [start](start/start.md)

## Integrations

-  [ai](ai/ai.md) Ask GPT-3 a question about the current debugging context.
-  [j](ida/j.md) Synchronize IDA's cursor with GDB.
-  [save_ida](ida/save_ida.md) Save the ida database.
-  [r2](radare2/r2.md) Launches radare2.
-  [r2pipe](radare2/r2pipe.md) Execute stateful radare2 commands through r2pipe.
-  [rz](rizin/rz.md) Launches rizin.
-  [rzpipe](rizin/rzpipe.md) Execute stateful rizin commands through rzpipe.
-  [rop](rop/rop.md) Dump ROP gadgets with Jon Salwan's ROPgadget tool.
-  [ropper](ropper/ropper.md) ROP gadget search with ropper.

## Linux/libc/ELF

-  [argc](argv/argc.md) Prints out the number of arguments.
-  [argv](argv/argv.md) Prints out the contents of argv.
-  [envp](argv/envp.md) Prints out the contents of the environment.
-  [aslr](aslr/aslr.md)
-  [auxv](auxv/auxv.md) Print information from the Auxiliary ELF Vector.
-  [elfsections](elf/elfsections.md) Prints the section mappings contained in the ELF header.
-  [gotplt](elf/gotplt.md) Prints any symbols found in the .got.plt section if it exists.
-  [plt](elf/plt.md) Prints any symbols found in the .plt section if it exists.
-  [got](got/got.md) Show the state of the Global Offset Table.
-  [track-got](got_tracking/track_got.md) Controls GOT tracking
-  [linkmap](linkmap/linkmap.md) Show the state of the Link Map
-  [errno](misc/errno_.md) Converts errno (or argument) to its string representation.
-  [piebase](pie/piebase.md) Calculate VA of RVA from PIE base.
-  [threads](tls/threads.md) List all threads belonging to the selected inferior.
-  [tls](tls/tls.md) Print out base address of the current Thread Local Storage (TLS).

## Misc

-  [asm](asm/asm.md) Assemble shellcode into bytes
-  [break-if-not-taken](branch/break_if_not_taken.md) Breaks on a branch if it is not taken.
-  [break-if-taken](branch/break_if_taken.md) Breaks on a branch if it is taken.
-  [checksec](checksec/checksec.md) Prints out the binary security settings using `checksec`.
-  [comm](comments/comm.md) Put comments in assembly code.
-  [cyclic](cyclic/cyclic_cmd.md) Cyclic pattern creator/finder.
-  [cymbol](cymbol/cymbol.md) Add, show, load, edit, or delete custom structures in plain C.
-  [dt](dt/dt.md)
-  [dumpargs](dumpargs/dumpargs.md) Prints determined arguments for call instruction.
-  [down](ida/down.md) Select and print stack frame called by this one.
-  [up](ida/up.md) Select and print stack frame that called this one.
-  [ipi](ipython_interactive/ipi.md) Start an interactive IPython prompt.
-  [stepuntilasm](next/stepuntilasm.md) Breaks on the next matching instruction.
-  [patch](patch/patch.md) Patches given instruction with given code or bytes.
-  [patch_list](patch/patch_list.md) List all patches.
-  [patch_revert](patch/patch_revert.md) Revert patch at given address.
-  [getfile](peda/getfile.md) Gets the current file.
-  [plist](plist/plist.md) Dumps the elements of a linked list.
-  [sigreturn](sigreturn/sigreturn.md) Display the SigreturnFrame at the specific address
-  [spray](spray/spray.md) Spray memory with cyclic() generated values
-  [tips](tips/tips.md) Shows tips.
-  [valist](valist/valist.md) Dumps the arguments of a va_list.

## Stack

-  [canary](canary/canary.md) Print out the current stack canary.
-  [retaddr](stack/retaddr.md) Print out the stack addresses that contain return addresses.
-  [stack](telescope/stack.md) Dereferences on stack data with specified count and offset.
-  [stackf](telescope/stackf.md) Dereferences on stack data, printing the entire stack frame with specified count and offset .

## pwndbg

-  [config](config/config.md) Shows pwndbg-specific configuration.
-  [configfile](config/configfile.md) Generates a configuration file for the current pwndbg options.
-  [theme](config/theme.md) Shows pwndbg-specific theme configuration.
-  [themefile](config/themefile.md) Generates a configuration file for the current pwndbg theme options.
-  [memoize](memoize/memoize.md)
-  [pwndbg](misc/pwndbg_.md) Prints out a list of all pwndbg commands.
-  [reinit_pwndbg](reload/reinit_pwndbg.md) Makes pwndbg reinitialize all state.
-  [reload](reload/reload.md) Reload pwndbg.
-  [bugreport](version/bugreport.md) Generate a bug report.
-  [version](version/version.md) Displays GDB, Python, and pwndbg versions.

## Context

-  [context](context/context.md) Print out the current register, instruction, and stack context.
-  [contextoutput](context/contextoutput.md) Sets the output of a context section.
-  [contextunwatch](context/contextunwatch.md) Removes an expression previously added to be watched.
-  [contextwatch](context/contextwatch.md)
-  [regs](context/regs.md) Print out all registers and enhance the information.
-  [xinfo](xinfo/xinfo.md) Shows offsets of the specified address from various useful locations.

## Register

-  [cpsr](cpsr/cpsr.md) Print out ARM CPSR or xPSR register.
-  [setflag](flags/setflag.md) Modify the flags register.
-  [fsbase](segments/fsbase.md) Prints out the FS base address. See also $fsbase.
-  [gsbase](segments/gsbase.md) Prints out the GS base address. See also $gsbase.

## Memory

-  [distance](distance/distance.md) Print the distance between the two arguments, or print the offset to the address's page base.
-  [hexdump](hexdump/hexdump.md) Hexdumps data at the specified address or module name.
-  [leakfind](leakfind/leakfind.md)
-  [mmap](mmap/mmap.md)
-  [mprotect](mprotect/mprotect.md)
-  [p2p](p2p/p2p.md) Pointer to pointer chain search. Searches given mapping for all pointers that point to specified mapping.
-  [telescope](p2p/ts.md) Recursively dereferences pointers starting at the specified address.
-  [telescope](peda/xprint.md) Recursively dereferences pointers starting at the specified address.
-  [probeleak](probeleak/probeleak.md)
-  [search](search/search.md) Search memory for byte sequences, strings, pointers, and integer values.
-  [telescope](telescope/telescope.md) Recursively dereferences pointers starting at the specified address.
-  [vmmap](vmmap/vmmap.md) Print virtual memory map pages.
-  [vmmap_add](vmmap/vmmap_add.md) Add virtual memory map page.
-  [vmmap_clear](vmmap/vmmap_clear.md) Clear the vmmap cache.
-  [vmmap_load](vmmap/vmmap_load.md) Load virtual memory map pages from ELF file.
-  [xinfo](xinfo/xinfo.md) Shows offsets of the specified address from various useful locations.
-  [memfrob](xor/memfrob.md) Memfrobs a region of memory (xor with '*').
-  [xor](xor/xor.md) XOR `count` bytes at `address` with the key `key`.

## Heap

-  [arena](heap/arena.md) Print the contents of an arena.
-  [arenas](heap/arenas.md) List this process's arenas.
-  [bins](heap/bins.md) Print the contents of all an arena's bins and a thread's tcache.
-  [fastbins](heap/fastbins.md) Print the contents of an arena's fastbins.
-  [find_fake_fast](heap/find_fake_fast.md) Find candidate fake fast or tcache chunks overlapping the specified address.
-  [heap](heap/heap.md) Iteratively print chunks on a heap.
-  [heap_config](heap/heap_config.md) Shows heap related configuration.
-  [hi](heap/hi.md) Searches all heaps to find if an address belongs to a chunk. If yes, prints the chunk.
-  [largebins](heap/largebins.md) Print the contents of an arena's largebins.
-  [malloc_chunk](heap/malloc_chunk.md) Print a chunk.
-  [mp](heap/mp.md) Print the mp_ struct's contents.
-  [smallbins](heap/smallbins.md) Print the contents of an arena's smallbins.
-  [tcache](heap/tcache.md) Print a thread's tcache contents.
-  [tcachebins](heap/tcachebins.md) Print the contents of a tcache.
-  [top_chunk](heap/top_chunk.md) Print relevant information about an arena's top chunk.
-  [try_free](heap/try_free.md) Check what would happen if free was called with given address.
-  [unsortedbin](heap/unsortedbin.md) Print the contents of an arena's unsortedbin.
-  [vis_heap_chunks](heap/vis_heap_chunks.md) Visualize chunks on a heap.

## Breakpoint

-  [ignore](ignore/ignore.md) Set ignore-count of breakpoint number N to COUNT.
-  [breakrva](pie/breakrva.md) Break at RVA from PIE base.

## Kernel

-  [kbase](kbase/kbase.md) Finds the kernel virtual base address.
-  [kchecksec](kchecksec/kchecksec.md) Checks for kernel hardening configuration options.
-  [kcmdline](kcmdline/kcmdline.md) Return the kernel commandline (/proc/cmdline).
-  [kconfig](kconfig/kconfig.md) Outputs the kernel config (requires CONFIG_IKCONFIG).
-  [klookup](klookup/klookup.md) Lookup kernel symbols.
-  [kversion](kversion/kversion.md) Outputs the kernel version (/proc/version).
-  [slab](slab/slab.md) Prints information about the slab allocator

## Process

-  [killthreads](killthreads/killthreads.md) Kill all or given threads.
-  [pid](procinfo/pid.md) Gets the pid.
-  [procinfo](procinfo/procinfo.md) Display information about the running process.

## Disassemble

-  [emulate](nearpc/emulate.md) Like nearpc, but will emulate instructions from the current $PC forward.
-  [nearpc](nearpc/nearpc.md) Disassemble near a specified address.

## Step/Next/Continue

-  [nextcall](next/nextcall.md) Breaks at the next call instruction.
-  [nextjmp](next/nextjmp.md) Breaks at the next jump instruction.
-  [nextproginstr](next/nextproginstr.md) Breaks at the next instruction that belongs to the running program.
-  [nextret](next/nextret.md) Breaks at next return-like instruction.
-  [nextsyscall](next/nextsyscall.md) Breaks at the next syscall not taking branches.
-  [stepover](next/stepover.md) Breaks on the instruction after this one.
-  [stepret](next/stepret.md) Breaks at next return-like instruction by 'stepping' to it.
-  [stepsyscall](next/stepsyscall.md) Breaks at the next syscall by taking branches.
-  [xuntil](peda/xuntil.md) Continue execution until an address or function.

## WinDbg

-  [bc](windbg/bc.md) Clear the breakpoint with the specified index.
-  [bd](windbg/bd.md) Disable the breakpoint with the specified index.
-  [be](windbg/be.md) Enable the breakpoint with the specified index.
-  [bl](windbg/bl.md) List breakpoints.
-  [bp](windbg/bp.md) Set a breakpoint at the specified address.
-  [da](windbg/da.md) Dump a string at the specified address.
-  [db](windbg/db.md) Starting at the specified address, dump N bytes.
-  [dc](windbg/dc.md) Starting at the specified address, hexdump.
-  [dd](windbg/dd.md) Starting at the specified address, dump N dwords.
-  [dds](windbg/dds.md) Dump pointers and symbols at the specified address.
-  [dq](windbg/dq.md) Starting at the specified address, dump N qwords.
-  [ds](windbg/ds.md) Dump a string at the specified address.
-  [dw](windbg/dw.md) Starting at the specified address, dump N words.
-  [eb](windbg/eb.md) Write hex bytes at the specified address.
-  [ed](windbg/ed.md) Write hex dwords at the specified address.
-  [eq](windbg/eq.md) Write hex qwords at the specified address.
-  [ew](windbg/ew.md) Write hex words at the specified address.
-  [ez](windbg/ez.md) Write a string at the specified address.
-  [eza](windbg/eza.md) Write a string at the specified address.
-  [go](windbg/go.md) Windbg compatibility alias for 'continue' command.
-  [k](windbg/k.md) Print a backtrace (alias 'bt').
-  [ln](windbg/ln.md) List the symbols nearest to the provided value.
-  [pc](windbg/pc.md) Windbg compatibility alias for 'nextcall' command.
-  [peb](windbg/peb.md) Not be windows.
