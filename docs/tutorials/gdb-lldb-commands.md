# GDB vs LLDB

For users who are migrating from one debugger to another, here is a table comparison of some of the most common actions and how to do them in GDB and LLDB. Note that both debuggers offer shorthands for typing these commands.

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
| **Start the Program at the First Instruction**| `starti`                               | `process launch --stop-at-entry`                            |
| **Enable ASLR**                               | `set disable-randomization off`        | `settings set target.disable-aslr false`                    |
