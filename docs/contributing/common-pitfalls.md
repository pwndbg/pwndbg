# Common pitfalls

## Imports

Lets reiterate some of the most important submodules in Pwndbg:

+ `pwndbg/dbg_mod` (also providing `pwndbg.dbg`) - Implements a lightweight debugger abstraction layer. Provides functionality that the underlying debugger is responsible for, like setting a breakpoint or writing to memory.
+ `pwndbg/aglib` - A library that uses `pwndbg/dbg_mod` to provide more complex operations, like operations on memory mappings (`pwndbg/aglib/vmmap.py`), registers (`pwndbg/aglib/regs_mod.py`), disassembly (`pwndbg/aglib/disasm/`) etc.
+ `pwndbg/lib` - Generic functionality that *does not* depend on anything "debugger related", like `pwndbg/lib/cache.py`, `pwndbg/lib/zig.py`, `pwndbg/lib/tempfile.py` etc.
+ `pwndbg/commands/` - Pwndbg commands implementations.

To keep this architecture coherent, maintainable, and prevent import cycles, there are a few things we need to obide by that we see being violated from time to time.

#### Only access pwndbg.lib when in pwndbg/lib

The `pwndbg/lib/` files must be importable from anywhere at anytime, they must not depend on any debugger state.
Thus, the only Pwndbg code you should be importing in a `pwndbg/lib` file, is another `pwndbg/lib` file. God forbid you do `import pwndbg.aglib` or use `pwndbg.dbg` **anywhere** in such a file (even in a non-top-level, function import).

#### Don't access aglib in pwndbg/dbg_mod

The `aglib` depends on `dbg_mod`, not the other way around. No `dbg_mod/` file should have a top-level `aglib`. Further, no `dbg_mod/` file should have an `aglib` import anywhere (even function-level). Currently the second rule is not followed, and stuff works, but lets not make it any worse.

#### Don't import commands

When a command is written, it is written with the user in mind and all that entails. This means appropriate error handling, message printing etc. A `pwndbg/command/` file has access to every submodule in Pwndbg. As such, it is **not** made to be used as an API for some other command/functionality. If there exists a command which you want to use as API, refactor it into an `aglib/` file, make sure there are no `print`s, make sure that it returns an error instead of silently eating it when appropriate etc.

Doing it this way prevents "fun" surprises, makes the code more maintanable, makes the dependancy graph cleaner and as such prevents import cycles.

#### `from pwndbg.aglib import arch` doesn't work

If you look at `pwndbg/aglib/__init__.py` you will see that `arch` is a None-initialized object and gets swapped out at runtime depending on which architecture we are debugging. As such, to get the correct information about the current architecture you must always do `aglib.arch.whatever()`.

#### `from pwndbg.aglib import regs` doesn't work

If you look at `pwndbg/aglib/__init__.py` you will see that `regs` is a None-initialized object and gets swapped out during initialization. To use it properly you must do `aglib.regs.whatever()`.

#### No `class module` magic

If you think you need a `class module`, you don't. Any amount of convenience you gain by that is dwarfed by the pain you bring to readability, maintainability, type system processing, LSP analysis etc.

#### Don't name the object the same as the file

The `pwndbg/dbg_mod/` folder used to be named `pwndbg/dbg/`, and had a singleton object also called `dbg` defined in `pwndbg/dbg/__init__.py`. `pwndbg/__init__.py` used to have this:
```python
from pwndbg import dbg as dbg_mod
from pwndbg.dbg import dbg as dbg
```
Don't do this. It inhibits readability, causes confusion on what is a submodule and what is an object when importing, messes with type analysis and LSP operations. If you can't think of an original name for your object, name your file `objname_mod.py`. It is a recognizable idiom in the codebase.

See https://github.com/pwndbg/pwndbg/pull/3492 for more info.
