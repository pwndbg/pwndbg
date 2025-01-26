# pwndbg

Pwndbg has a great deal of useful features.  You can a list all available commands at any time by typing the `pwndbg` command. It can also be configured: see `config` and `theme` commands. Below is a subset of them which are easy to capture in screenshots.

## GDB vs LLDB
| **Functionality**                             | **GDB Command**                        | **LLDB Command**                                            |
|-----------------------------------------------|----------------------------------------|-------------------------------------------------------------|
| **Start Debugging Program**                   | `gdb ./your-program`                   | `lldb ./your-program`                                       |
| **Set a Breakpoint**                          | `break <function-name>`                | `breakpoint set --name <function-name>`                     |
| **Set Breakpoint on Address**                 | `break *<address>`                     | `breakpoint set --address <address>`                        |
| **Set Breakpoint at Line**                    | `break <filename>:<line-number>`       | `breakpoint set --file <filename> --line <line-number>`     |
| **Set Hardware Breakpoint**                   | `hbreak <function-name>`               | `breakpoint set --hardware --name <function-name>`          |
| **Set Hardware Breakpoint at Memory**         | `hbreak *<memory-address>`             | `breakpoint set --hardware --address <memory-address>`      |
| **List All Breakpoints**                      | `info breakpoints`                     | `breakpoint list`                                           |
| **Delete Breakpoints**                        | `delete <breakpoint-number>`           | `breakpoint delete <breakpoint-number>`                     |
| **Set Watchpoint**                            | `watch <variable>`                     | `watchpoint set variable <variable>`                        |
| **Set Conditional Breakpoint**                | `break <function-name> if <condition>` | `breakpoint set --condition "<condition>"`                  |
| **Continue Execution**                        | `continue`                             | `process continue`                                          |
| **Next Instruction**                          | `next`                                 | `thread step-over`                                          |
| **Step into a Function**                      | `step`                                 | `thread step-in`                                            |
| **Step out of a Function**                    | `finish`                               | `thread step-out`                                           |
| **Print Threads**                             | `info threads`                         | `thread list`                                               |
| **Select Thread**                             | `thread <thread-id>`                   | `thread select <thread-id>`                                 |
| **Print Register Values**                     | `info registers`                       | `register read -a`                                          |
| **Print a Variable**                          | `print <variable>`                     | `print <variable>`                                          |
| **Display Variable on Every Stop**            | `display <variable>`                   | `expression --watch <variable>`                             |
| **Examine Memory (Hex)**                      | `x/<num>x <memory-address>`            | `memory read --format x --count <num> <memory-address>`     |
| **Examine Memory (Integer)**                  | `x/<num>d <memory-address>`            | `memory read --format d --count <num> <memory-address>`     |
| **Inspect Stack Trace**                       | `backtrace`                            | `thread backtrace`                                          |
| **Change Register Value**                     | `set $<register-name> = <value>`       | `register write <register-name> <value>`                    |
| **Check Program Status**                      | `info locals`                          | `frame variable`                                            |
| **Check Program Info**                        | `info functions`                       | `image lookup --functions`                                  |
| **Show Disassembly of Function**              | `disas <function-name>`                | `disassemble <function-name>`                               |
| **Memory Dump (Hex)**                         | `x/<num>xh <memory-address>`           | `memory read --format x --count <num> <memory-address>`     |
| **Memory Dump (Bytes)**                       | `x/<num>bx <memory-address>`           | `memory read --format b --count <num> <memory-address>`     |
| **Show Process Information**                  | `info process`                         | `process status`                                            |
| **Quit Debugging**                            | `quit`                                 | `quit`                                                      |
| **Run Program with Arguments**                | `run <arg1> <arg2> ...`                | `process launch -- <arg1> <arg2> ...`                       |
| **Show Current Function**                     | `info frame`                           | `frame info`                                                |
| **Set Sysroot**                               | `set sysroot <path-to-sysroot>`        | `settings set target.sysroot <path-to-sysroot>`             |
| **Set Source Directory**                      | `directory <path-to-source-directory>` | `settings set target.source-map <remote-path> <local-path>` |
| **Set Architecture**                          | `set architecture <arch>`              | `target create --arch <arch> <executable-file>`             |
| **Show Settings**                             | `show <setting-name>`                  | `settings show <setting-name>`                              |
| **Set File for Debugging**                    | `file <executable-file>`               | `target create <executable-file>`                           |
| **Start the Program and Run One Instruction** | `starti`                               | `process launch --stop-at-entry`                            |
| **Enable ASLR**                               | `set disable-randomization off`        | `settings set target.disable-aslr false`                    |

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

The output of the context may be redirected to a file (including other tty) by using `set context-output /path/to/file` while leaving other output in place.

![](caps/context.png)

A history of previous context output is kept which can be accessed using the `contextprev` and `contextnext` commands.

### Splitting / Layouting Context

The context sections can be distributed among different tty by using the `contextoutput` command.
Example: `contextoutput stack /path/to/tty true`

Python can be used to create a tmux layout when starting pwndbg and distributing the context among
the splits.
```python
python
import atexit
import os
from pwndbg.commands.context import contextoutput, output, clear_screen
bt = os.popen('tmux split-window -P -F "#{pane_id}:#{pane_tty}" -d "cat -"').read().strip().split(":")
st = os.popen(F'tmux split-window -h -t {bt[0]} -P -F '+'"#{pane_id}:#{pane_tty}" -d "cat -"').read().strip().split(":")
re = os.popen(F'tmux split-window -h -t {st[0]} -P -F '+'"#{pane_id}:#{pane_tty}" -d "cat -"').read().strip().split(":")
di = os.popen('tmux split-window -h -P -F "#{pane_id}:#{pane_tty}" -d "cat -"').read().strip().split(":")
panes = dict(backtrace=bt, stack=st, regs=re, disasm=di)
for sec, p in panes.items():
  contextoutput(sec, p[1], True)
contextoutput("legend", di[1], True)
atexit.register(lambda: [os.popen(F"tmux kill-pane -t {p[0]}").read() for p in panes.values()])
end
```
If you like it simple, try configuration with [splitmind](https://github.com/jerdna-regeiz/splitmind)

![](caps/context_splitting.png)

Note above example uses splitmind and following configuration:

```python
python
import splitmind
(splitmind.Mind()
  .tell_splitter(show_titles=True)
  .tell_splitter(set_title="Main")
  .right(display="backtrace", size="25%")
  .above(of="main", display="disasm", size="80%", banner="top")
  .show("code", on="disasm", banner="none")
  .right(cmd='tty; tail -f /dev/null', size="65%", clearing=False)
  .tell_splitter(set_title='Input / Output')
  .above(display="stack", size="75%")
  .above(display="legend", size="25")
  .show("regs", on="legend")
  .below(of="backtrace", cmd="ipython", size="30%")
).build(nobanner=True)
end
```

#### GDB TUI
The context sections are available as native [GDB TUI](https://sourceware.org/gdb/current/onlinedocs/gdb.html/TUI.html) windows named `pwndbg_[sectionname]`.

There are some predefined layouts coming with pwndbg which you can select using `layout pwndbg` or `layout pwndbg_code`.

To create [your own layout](https://sourceware.org/gdb/current/onlinedocs/gdb.html/TUI-Commands.html) and selecting it use normal `tui new-layout` syntax like:
```
tui new-layout pwndbg_custom {-horizontal { { -horizontal { pwndbg_code 1 pwndbg_disasm 1 } 2 { {-horizontal pwndbg_legend 8 pwndbg_control 2 } 1 pwndbg_regs 6 pwndbg_stack 6 } 3 } 7 cmd 3 } 3 { pwndbg_backtrace 2 pwndbg_threads 1 pwndbg_expressions 2 } 1 } 1 status 1
layout pwndbg_custom
```

![](caps/context_tui.png)

Use `focus cmd` to focus the command window and have the arrow keys scroll through the command history again. `tui disable` to disable TUI mode and go back to CLI mode when running commands with longer output. `ctrl-x + a` toggles between TUI and CLI mode quickly. Hold shift to ignore the TUI mouse integration and use the mouse normally to select text or copy data.

### Watch Expressions

You can add expressions to be watched by the context.
Those expressions are evaluated and shown on every context refresh.

An expression can be added via the `contextwatch` command (aliased `ctx-watch` and `cwatch`).

Per default an expression is parsed and evaluated in the debugged language and can be added with:
```
contextwatch BUF
ctx-watch ITEMS[0]
```

Alternatively one can provide an arbitrary gdb command to be executed and the result printed in the
context by using the optional `cmd` parameter with the value `execute`:
```
contextwatch execute "ds BUF"
cwatch execute "x/20x $rsp"
```

### Ghidra

With the help of [radare2](https://github.com/radareorg/radare2) or [rizin](https://github.com/rizinorg/rizin) it is possible to show the
decompiled source code of the ghidra decompiler.

However, this comes with some prerequisites.
* First: you have to have installed radare2 or rizin and it must be found by gdb (within path)
* Second: you have to install the ghidra plugin for radare2
  [r2ghidra](https://github.com/radareorg/r2ghidra) or install the ghidra plugin for rizin [rz-ghidra](https://github.com/rizinorg/rz-ghidra)

* Third: r2pipe has to be installed in the python-context gdb is using (or if you are using rizin, install rzpipe instead)

The decompiled source be shown as part of the context by adding `ghidra` to `set context-sections`
or by calling `ctx-ghidra [function]` manually.

Be warned, the first call to both radare2/r2ghidra and rizin/rz-ghidra are rather slow! Subsequent requests for decompiled
source will be faster. And it does take up some resources as the radare2/rizin instance is kept by r2pipe/rzpipe
to enable faster subsequent analysis.

With those performance penalties it is reasonable to not have it launch always. Therefore it includes
an option to only start it when required with `set context-ghidra`:
* `set context-ghidra always`: always trigger the ghidra context
* `set context-ghidra never`: never trigger the ghidra context except when called manually
* `set context-ghidra if-no-source`: invoke ghidra if no source code is available

Remark: the plugin tries to guess the correct current line and mark it with "-->", but it might
get it wrong.

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
![](caps/heap_fake_fast.png)
![](caps/heap_try_free.png)

## IDA Pro/Binary Ninja Integration

Pwndbg is capable of integrating with IDA Pro or Binary Ninja by installing an XMLRPC server in the decompiler as a plugin, and then querying it for information.

This allows extraction of comments, decompiled lines of source, breakpoints, symbols, and synchronized debugging (single-steps update the cursor in the decompiler).

![](caps/ida_comments.png)
![](caps/ida_function.png)
![](caps/ida_integration.png)

See the [Binary Ninja integration guide](docs/binja_integration.md) for setup information.

## Go Debugging

Pwndbg has support for dumping complex Go values like maps and slices, including automatically parsing out type layouts in certain cases.

See the [Go debugging guide](docs/go_debugging.md) for more information.

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

## Finding Leaks
![](caps/leakfind.png)
Finding leak chains can be done using the `leakfind` command. It recursively inspects address ranges for pointers, and reports on all pointers found.


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
