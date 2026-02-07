# Implementing Libc support

A [C Standard Library](https://en.wikipedia.org/wiki/C_standard_library) (libc) is the standard library for C. Other languages will also very often interface with the libc to avoid reimplementing all the operating system interfacing. As such, the libc is used by almost every dynamically linked program on a given system.

In Pwndbg, support for a given libc implementation is provided by a `pwndbg/libc/<name of libc>.py` file, which implements the `pwndbg.libc.dispatch.LibcProvider` protocol. Currently, the [GNU C Library (glibc)](https://sourceware.org/glibc/) and [musl](https://musl.libc.org/) are supported.

Note that you can freely use Pwndbg with programs compiled with other libc's, when we say we "support libc X", that means "there are features that we provide that are specific to libc X" and specifically, the `libcinfo` command will not return "unknown"for a supported libc.

Interestingly, although we do not yet support bionic (the android libc), we do support jemalloc. The mallocng (musl allocator) code and the glibc allocator code do depend on the `pwndbg/libc/musl.py` and `pwndbg/libc/glibc.py` implementations, as they should. Historically in Pwndbg, too much of the libc-specific code has actually been part of allocator-specific code. We want to separate this out so other subsystems that do not care about the allocator can use libc-specific features.

## Scaffolding

Say you want to add bionic support. You would create a `pwndbg/libc/bionic.py` file, implement all the functions specified in `pwndbg.libc.dispatch.LibcProvider` there, and add the `bionic` module to `pwndbg.libc.facade._libc_implementations`. After you implement all the functions, you would add a test file called `test_bionic.py`, equivalent to the one called `test_musl.py`.

For development, it will be necessary for you to get the source code of the libc, to know how to compile it, and to know how to dynamically and statically link programs with it.

For all of the binutils tools used below (e.g. `nm`, `objcopy`, `readelf`) you can use the LLVM version of the same tool (`llvm-nm`, `llvm-objcopy`, `llvm-readelf`) if you are operating on cross-architecture binaries since the default binutils package on most distributions only supports the host architecture, while the LLVM ones have support for all architectures baked in.

## Note on static linking

It is very hard to robustly support libc-specific features for statically compiled binaries,
so this is really best effort.

## Glossary

### exported symbol

Dynamic libraries have some set of functions that are a part of their API, i.e. that are callable from other object files. Even if you strip a dynamic library, these symbols will still be retained. We call these "**exported symbols**", they are also called "dynamic symbols". They are located in the `.dynsym` section, and their names in the `.dynstr` section of the binary. You can dump them with:
```{.bash .copy}
nm -D libc.so
```
or (better)
```{.bash .copy}
readelf --dyn-syms --extra-sym-info libfoo.so
```

Symbols can be either functions or global variables.

If a libc is dynamically linked, these should be always present. If a libc is statically linked, they usually aren't. We expect some exported symbols to be present in all dynamic libraries (e.g. `scanf`, `exit`, `printf`, ...) because they are part of the C standard, but some may be libc-specific (e.g. `__freadahead` is provided by musl and bionic but not by glibc).

### debug info

I.e. debugging information. The stuff you get when you compile with `-g`: line numbers, structures, function-local variables...

For us, the most important thing is **types**. It is much better if we can extract a type like e.g. `struct malloc_chunk` from the debug info itself, rather than having to guess the layout ourselves. This is for two main reasons:

1. The structure may change between versions, so in case we haven't caught up with the newest libc version (or version detection is hard), users with debug info will be able to debug without issues.
2. By using the type from debug info, we support forks, intermediate versions, and custom patches of the libc, rather than just the main versions which are distributed by linux distros.

If debugging information is present, I also expect exported symbols and internal symbols to also be present.

A very convenient thing is that often, debug info can be automatically recovered with [debuginfod](https://sourceware.org/elfutils/Debuginfod.html) without recompiling the libc.

### internal symbols

An internal symbol is a symbol which is not an exported (dynamic) symbol. You can see these by simply calling:
```{.bash .copy}
$ nm libc.so
nm: libc.so: no symbols
# ^ This is the default on distros
```
An example is `__libc_version` on glibc and musl. 

## Implementing the LibcProvider functions

Read the docstrings in `pwndbg.libc.dispatch` so we are on the same page.

The functions `type`, `urls`, `libc_same_as_ld` are trivial to implement.

### Treasure hunt

In the libc's repo you will be using `git tag` a lot. You will be looking for symbols and patterns that fulfill certain criteria, and among other things, have been present in the codebase for a while. There are a bunch of programs out there compiled against ancient versions of various libc's, and we would like to support them.

For all functions which reference a symbol from the libc, you must specify in which version that symbol was added, what year that was, and a permalink to the definition of that symbol in its first version. For example:
```python
# The __polevll symbol is an internal symbol in musl. Doesn't exist in bionic nor glibc.
# It was added in version v0.8.7 (year 2012).
# https://elixir.bootlin.com/musl/v0.8.7/source/src/math/__polevll.c#L63
```

### version

The easiest way to check if your libc has its version embedded is to grep for it (i.e. grep for the `git tag` you compiled for)
```{.bash .copy}
$ strings libc.so.6 | grep 2.42
GLIBC_2.42
glibc 2.42
NPTL 2.42
GNU C Library (GNU libc) stable release version 2.42.
```
Here we can see it is clearly there. If it isn't you're going to have to get creative.

If you're lucky, your libc provides the version as a symbol. For both musl and glibc this is `__libc_version`. Unfortunately, musl has only recently (2019) started providing its version in the build of the ELF. Unfortunately^2, both for glibc and musl `__libc_version` is an internal symbol. Meaning that if you don't have internal symbols, you need another way to recover the version. This can be done by scanning the appropriate section in the libc ELF, see `pwndbg.libc.glibc._get_version()`.

### has_debug_info

This should be easy, just find a struct which has existed since first version of the libc and still exists.

### has_internal_symbols

Intuitively, these symbols will usually be prefixed with `_` or `__` so they shouldn't be hard to find. There is however, an important gotcha.

There exists a thing called [MiniDebugInfo](https://www.sourceware.org/gdb/current/onlinedocs/gdb.html/MiniDebugInfo.html), which allows for shipping some minimal debugging information for the purposes of having symbolicated backtraces. Fedora for instance uses this to ship musl (and probably everything else?), which caused me a very fun [debugging](https://github.com/pwndbg/pwndbg/actions/runs/21156585707/job/60842550639?pr=3637) session.
This debugging information is placed in the `.gnu_debugdata` section, encrypted with LZMA. You can extract the contained symbols like this:
```{.bash} {.copy}
objcopy --dump-section .gnu_debugdata=minidebuginfo.xz libc.so
xz -d minidebuginfo.xz
readelf --syms minidebuginfo
```

In practice, this thing can easily contain internal function symbols, but **not** internal global variables. This kinda sucks, as in these cases the `has_internal_symbols` function should return `False`, and in general having internal global variables can be really handy for us.

For most of the LibcProvider functions, a false-negative is much more acceptible than a false-positive, because a false-negative will usually just cause a fallback to a heuristic, whereas a false-positive can lead to wrong deductions.

If there comes a need in the future, we could modify LibcProvider to contain `has_internal_function_symbols` and `has_internal_variable_symbols`, and then make `has_internal_symbols` just be defined in the facade.py and return `has_internal_function_symbols() and has_internal_variable_symbols()`. Lets not complicate it though until there is a need for it.

Anyway, for `has_internal_symbols` to be robust against MiniDebugInfo, you must find a non-exported global variable (that has existed for a long time and still exists). You can use these commands to help you out, compile the libc with debugging information and then:
```{.bash .copy}
readelf --syms --wide libc.so | awk '{print $4, $5, $6, $7, $8}' | sort -u > all-syms.txt
readelf --dyn-syms --wide libc.so | awk '{print $4, $5, $6, $7, $8}' | sort -u > dyn-syms.txt
comm -23 all-syms.txt dyn-syms.txt > internal-syms.txt
grep "OBJECT" internal-syms.txt > internal-vars.txt
```
Now look at `internal-vars.txt` and find a symbol which has existed for a long time. If possible, it should also be an obscure one that is unlikely to exist in some other object file in a program, though this is not crucial. They are usually the `static` global variables in the source.

To easily test that the symbol does not show up when the libc is stripped you may:
```{.bash .copy}
cp libc.so libc.so.debug
strip libc.so
```

### verify_libc_candidate

This should only return True when we are certain. I don't think there is a good tip for this other than to look at the existing implementations. Searching inside `.rodata` has been a successful strategy.

### verify_ld_candidate 

You don't need to implement this if you implemented `verify_libc_candidate`. Unless `libc_same_as_ld()` returns `True`, then `verify_ld_candidate` must call `verify_libc_candidate`.

## Compiling the libc

Compiling a libc, and compiling a program *with* a libc, can have its quirks. Whenever you add support for a new libc in Pwndbg, write here the compilation instructions so future contributors can easily reference them.

If you are using [`clangd`](https://github.com/clangd/clangd) as your C/C++ Language Server Protocol (LSP) implementation, and are not using a full IDE, you likely want to generate a `compile_commands.json` file which will allow `clangd` to properly implement Go-To-Definition actions etc. You usually do this via [`bear`](https://github.com/rizsotto/Bear) i.e. you would run `bear -- make` instead of just `make`, which will create a `compile_commands.json` file in the current folder which `clangd` will consume automatically. An alternative to `bear` is [`compiledb`](https://github.com/nickdiego/compiledb). Sometimes one works better, sometimes the other, it's a bit of a gamble. Anyway, these tools are not necessary for a successful compilation, so if you see `compiledb whatever_actual_command` below, that means you can just as well run `whatever_actual_command`.

### glibc

Mostly taken from this stackoverflow answer: https://stackoverflow.com/questions/10412684/how-to-compile-my-own-glibc-c-standard-library-from-source-and-use-it . Official instructions: https://sourceware.org/glibc/wiki/Testing/Builds .

```bash
git clone git://sourceware.org/git/glibc.git
cd glibc
mkdir -p build/install
cd build
export GLIBC_INSTALL="$(pwd)/install" && echo $GLIBC_INSTALL
../configure --prefix $GLIBC_INSTALL
# hmm I can't get bear nor compiledb working atm.
make -j $(nproc)
make install
# cp compile_commands.json ../.
```
The libc and ld are in `$GLIBC_INSTALL/lib/`.

#### dynamically compiling with glibc

Make sure that GLIBC_INSTALL is set in this shell session. 
```bash
[ -n "$GLIBC_INSTALL" ] && gcc \
  -L "$GLIBC_INSTALL/lib" \
  -I "$GLIBC_INSTALL/include" \
  -Wl,--rpath="$GLIBC_INSTALL/lib" \
  -Wl,--dynamic-linker="$GLIBC_INSTALL/lib/ld-linux-x86-64.so.2" \
  -o main \
  main.c
```
You can check that everything is fine with `ldd main`. Also by opening the binary in Pwndbg and running `start`, `vmmap` and optionally `libcinfo`.

#### statically compiling with glibc

Not officially supported but it kinda works:
```bash
[ -n "$GLIBC_INSTALL" ] && gcc \
  -L "$GLIBC_INSTALL/lib" \
  -I "$GLIBC_INSTALL/include" \
  -Wl,--rpath="$GLIBC_INSTALL/lib" \
  -Wl,--dynamic-linker="$GLIBC_INSTALL/lib/ld-linux-x86-64.so.2" \
  -static \
  -o main \
  main.c
```

#### cleaning the compilation
```bash
rm -rf build
```

### musl

Official instructions: https://git.musl-libc.org/cgit/musl/tree/INSTALL .

```bash
git clone git://git.musl-libc.org/musl
cd musl
mkdir -p build/lib
export MUSL_INSTALL=$(pwd)/build && echo $MUSL_INSTALL
./configure --enable-debug --prefix=$MUSL_INSTALL --syslibdir=$MUSL_INSTALL/lib
compiledb make -j $(nproc)
make install
```
The libc and ld are in `$MUSL_INSTALL/lib/`.

#### dynamically compiling with musl
```bash
[ -n "$MUSL_INSTALL" ] && $MUSL_INSTALL/bin/musl-gcc \
  -L $MUSL_INSTALL/lib \
  -Wl,-rpath=$MUSL_INSTALL/lib \
  -o main \
  main.c
```
Some older musl versions also require passing `--no-pie`.

#### statically compiling with musl
```bash
[ -n "$MUSL_INSTALL" ] && $MUSL_INSTALL/bin/musl-gcc \
  -L $MUSL_INSTALL/lib \
  -static \
  -o main \
  main.c 
```

#### cleaning the compilation
```bash
make clean
make distclean
mv .gitignore ../nya1234
git clean --force
mv ../nya1234 .gitignore
rm -rf build
```

