# Symbol (de)mangling

✨ The crash course on how to handle it when debugging. ✨

In C++ (and lots of languages that want to talk to C) there exists "symbol name mangling". Essentially what this means is that each symbol name has two representations:

1. The actual symbol name as the compiler/debugger/toolchain sees it (the "mangled" name i.e. the "linkage" name)
2. The "pretty" symbol name that is human-readable (the "demangled" name)

For example, a C++ mangled/linkage name is
```
_ZN6burger13prepare_orderENS_12OrderRequestE.resume
```
and its demangled name is
```cpp
burger::prepare_order(burger::OrderRequest) [clone .resume]
```

The mangling algorithm is language/compiler/ABI-defined.

## Debugging

Right so generally if you're a moderately sane person you will prefer to see `burger::prepare_order(burger::OrderRequest) [clone .resume]` rather than `_ZN6burger13prepare_orderENS_12OrderRequestE.resume`. In GDB there are two configs that control this (see `apropos mangle`):

+ `set print demangle`     (on by default)  - controls the output of stuff like `info sym <addr>`
+ `set print asm-demangle` (off by default) - controls the output of `disass`

Pwndbg doesn't override these settings. If you're using Pwndbg you should be using `u`/`nearpc` rather than `disass`, which shows the nice demangled names. The disassembly context also shows the demangled names. I would thus recommend leaving `print asm-demangle` to off (the default) so you can read out mangled names from somewhere.

To make expression evaluation unambiguous in the case of demangled symbols (which contain all sorts of characters), GDB allows you to signify a symbol or type lookup with single quotes (`' '`). Remember this, this is very useful!

Using that, the easiest way to **get the address** of a symbol is by wrapping it in `&'symbol'`, which works for both demangled and mangled names:
```
pwndbg> p &'burger::prepare_order(burger::OrderRequest) [clone .resume]'
$1 = (burger::Task (*)(burger::OrderRequest)) 0x555555556f80 <burger::prepare_order(burger::OrderRequest) [clone .resume]>

pwndbg> p &'_ZN6burger13prepare_orderENS_12OrderRequestE.resume'
$2 = (burger::Task (*)(burger::OrderRequest)) 0x555555556f80 <burger::prepare_order(burger::OrderRequest) [clone .resume]>
```
Alternatively, you can also use GDBs `info addr` to get the address of a (de)mangled symbol, without any quotes necessary.

If you have a **mangled name** and would like to see **how it is demangled**, you can use GDBs `demangle` command:
```
pwndbg> demangle _ZN6burger13prepare_orderENS_12OrderRequestE.resume
burger::prepare_order(burger::OrderRequest) [clone .resume]
```
If GDB is trolling you with `❌ Can't demangle "..."`, try setting the language explicitly with `demangle -l c++ the_mangled_name`.

If you have a **demangled** name and would like to see **how it is mangled**, the best I got is:
```
pwndbg> x &'burger::prepare_order(burger::OrderRequest) [clone .resume]'
0x555555556f80 <_ZN6burger13prepare_orderENS_12OrderRequestE.resume>:	0xfa1e0ff3
#                       ^^ copy mangled name from here
```
Which is why I recommend keeping `print asm-demangle` off.

If you want to use a demangled symbol in a GDB / Pwndbg command, make sure to use the single quotes (`' '`). And remember, they don't mean the same thing as double quotes!

+ Single quote mean **this is a symbol/type**
+ Double quotes mean **this is one expression/argument/token**

Here is an expression that exercises both:
```
pwndbg> dist 'burger::Shop::~Shop()'+123     "123 + 'burger::Shop::~Shop()' + 456 * 2"
0x555555558d6b->0x5555555590fb is 0x390 bytes (0x72 words)
```
(We get away with not using `&` here because the symbol is a function.)

If you're trying to **find** the name of a symbol whose name you remember vaguely, or whose name you know from source, your best bet is hoping for a partial match in `info func`:
```
pwndbg> info func prepare_order
All functions matching regular expression "prepare_order":

File awaiting_burgers.cpp:
379:	burger::Task burger::prepare_order(burger::OrderRequest) [clone .destroy];
379:	burger::Task burger::prepare_order(burger::OrderRequest) [clone .resume];
#         ^^^^^^^^ make sure not to copy the return type
#                                         make sure not to copy the semi-colon ^
# then you can get its address like we discussed:
pwndbg> p &'burger::prepare_order(burger::OrderRequest) [clone .resume]'
$1 = (burger::Task (*)(burger::OrderRequest)) 0x555555556f80 <burger::prepare_order(burger::OrderRequest) [clone .resume]>
```
Trying to use tab-completion for this will usually mess you up, I wouldn't recommend it.

### Value resolution matrix

Two things you need to remember: `'symbol'` gives you the *value* of the symbol. In GDB, the *value* of
a function symbol is the address of the function. This gives you the following cases of things that
can happen

If you have debug info:

+ `p 'func symbol'`: gives you the address of the function
+ `p &'func symbol'`: gives you the address of the function
+ `p 'variable symbol'`: gives you the **value** of the variable
+ `p &'variable symbol'`: gives you the address of the variable

If you don't have debug info (specifically, the type info for this symbol):

+ `p 'func symbol'` : gives you the address of the function
+ `p &'func symbol'`: gives you the address of the function
+ `p 'variable symbol'`: gives you a "no debug info (type info)" **error**; you need to cast the variable to the appropriate type
+ `p &'variable symbol'`: gives you the address of the variable

### Calling a demangled function

Not such a common case but good to know how to do it. If you have debug info you can do it like this:
```
pwndbg> p 'Vec::operator<=>(Vec const&) const'(param1, param2)
$1 = 0xff
```
If you don't have debug info, you need to cast the function type:
```
pwndbg> p ((signed char (*)(void *, void *))'Vec::operator<=>(Vec const&) const')(param1, param2)
$2 = 0xff
```
The format is `((function type)'function name')(param1, param2)`. If you want to run this monstrosity as part of a bigger Pwndbg command, wrap the whole thing in double quotes.

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

When interacting with debugger API and output of commands like `info sym`, be aware that if you're interacting with demangled names, there be dragons. You should expect symbol names to have spaces, dots, pluses (`operator+`), digits, etc etc. See the `test_weird_symbols.py` file for every weirdness we could come up with.

## References

+ [handwiki/overview of language mangling](https://handwiki.org/wiki/Name_mangling)
+ [C++ mangling algo](https://itanium-cxx-abi.github.io/cxx-abi/abi.html#mangling)
+ [rust](https://doc.rust-lang.org/rustc/symbol-mangling/index.html) mangling [algorithm](https://doc.rust-lang.org/rustc/symbol-mangling/v0.html)
+ [pwndbg/debugging C++](./debugging-cxx.md)
+ [why GDB expressions are cooked and what we do about them](https://github.com/pwndbg/pwndbg/issues/4189)


