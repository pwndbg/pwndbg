# Symbol (de)mangling

✨ The crash course on how to handle it when debugging. ✨

In C++ (and lots of languages that want to talk to C) there exists "symbol name mangling". Essentially what this means
is that each symbol name has two representations:

1. The actual symbol name as the compiler/debugger/toolchain sees it (the "mangled" name)
2. The "pretty" symbol name that is human-readable (the "demangled" name)

For example, a C++ mangled name is
```
_ZN6burger13prepare_orderENS_12OrderRequestE.resume
```
and its demangled name is
```cpp
burger::prepare_order(burger::OrderRequest) [clone .resume]
```

The mangling algorithm is language/compiler/ABI-defined.

## Debugging

Right so generally if you're a moderately sane person you will prefer to see `burger::prepare_order(burger::OrderRequest) [clone .resume]`
rather than `_ZN6burger13prepare_orderENS_12OrderRequestE.resume`. In GDB there are two configs that control this (see `apropos mangle`):

+ `set print demangle`     (on by default)  - controls the output of stuff like `info sym <addr>`
+ `set print asm-demangle` (off by default) - controls the output of `disass`

Pwndbg doesn't override these settings. If you're using Pwndbg you should be using `nearpc` rather than `disass`, which shows the nice demangled names.
The disassembly context also shows the demangled names. I would thus recommend leaving `print asm-demangle` to off (the default)
so you can read out mangled names from somewhere.

If you would like to **get the address** of a symbol, GDBs `info addr` works for both demangled and mangled names:
```
(gdb) info addr burger::prepare_order(burger::OrderRequest) [clone .resume]
Symbol "burger::prepare_order(burger::OrderRequest) [clone .resume]" is at 0x555555556f80 in a file compiled without debugging.

(gdb) info addr _ZN6burger13prepare_orderENS_12OrderRequestE.resume
Symbol "_ZN6burger13prepare_orderENS_12OrderRequestE.resume" is at 0x555555556f80 in a file compiled without debugging.
```
Make sure you don't leave any offset there, i.e. this doesn't work:
```
#                         offset that often shows up in disassembly \/ 
(gdb) info addr _ZN6burger13prepare_orderENS_12OrderRequestE.resume+123
❌ No symbol "_ZN6burger13prepare_orderENS_12OrderRequestE.resume+123" in current context.
```

If you have a **mangled name** and would like to see **how it is demangled**, you can use GDBs `demangle` command:
```
(gdb) demangle _ZN6burger13prepare_orderENS_12OrderRequestE.resume
burger::prepare_order(burger::OrderRequest) [clone .resume]
```
If GDB is trolling you with `❌ Can't demangle "..."`, try setting the language explicitly with `demangle -l c++ the_mangled_name`.

If you have a **demangled** name and would like to see **how it is mangled**, I don't know how to do this. The best I got is:
```
(gdb) info addr burger::prepare_order(burger::OrderRequest) [clone .resume]
Symbol "burger::prepare_order(burger::OrderRequest) [clone .resume]" is a function at address 0x555555556f80.
#                                                                                    copy address ^^
(gdb) x 0x555555556f80
    0x555555556f80 <_ZN6burger13prepare_orderENS_12OrderRequestE.resume>:	endbr64
#                       ^^ copy mangled name from here
```
Which is why I recommend keeping `print asm-demangle` off.

The fact that mangling can't be done with one command is quite annoying, because most GDB/Pwndbg commands don't play well with demangled
names:
```
(gdb) x/20i burger::prepare_order(burger::OrderRequest) [clone .resume]
❌ A syntax error in expression, near `::OrderRequest) [clone .resume]'.
```
So most often if you need to do some operation, just **taking the address** with `info addr` and passing that as the argument is the play.

If you're trying to **find** the name of a symbol whose name you remember vaguely, or whose name you know from source, your best bet
is hoping for a partial match in `info func`:
```
(gdb) info func prepare_order
All functions matching regular expression "prepare_order":

File awaiting_burgers.cpp:
379:	burger::Task burger::prepare_order(burger::OrderRequest) [clone .destroy];
379:	burger::Task burger::prepare_order(burger::OrderRequest) [clone .resume];
#         ^^^^^^^^ make sure not to copy the return type
#                                         make sure not to copy the semi-colon ^
# then you can get its address like we discussed:
(gdb) info burger::prepare_order(burger::OrderRequest) [clone .resume]
Symbol "burger::prepare_order(burger::OrderRequest) [clone .resume]" is a function at address 0x555555556f80.
```
Trying to use tab-completion for this will usually mess you up, I wouldn't recommend it.

## Out of the debugger

To get a demangled name from a mangled name, you can also use the tooling from your toolchain:
```
$ # from binutils
$ c++filt _ZN6burger13prepare_orderENS_12OrderRequestE.resume
burger::prepare_order(burger::OrderRequest) [clone .resume]

$ # from llvm
$ llvm-cxxfilt _ZN6burger13prepare_orderENS_12OrderRequestE.resume
burger::prepare_order(burger::OrderRequest) (.resume)
```
The names are slightly different, fun right??

## Programming

When interacting with debugger API and output of commands like `info sym`, be aware that if you're interacting with
demangled names, there be dragons. You should expect symbol names to have spaces, dots, pluses (`operator+`), digits, etc etc.

## References

+ [handwiki/overview of language mangling](https://handwiki.org/wiki/Name_mangling)
+ [C++ mangling algo](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#mangling)
+ [rust](https://doc.rust-lang.org/rustc/symbol-mangling/index.html) mangling [algorithm](https://doc.rust-lang.org/rustc/symbol-mangling/v0.html)
+ [pwndbg/debugging C++](./debugging-cxx.md)


