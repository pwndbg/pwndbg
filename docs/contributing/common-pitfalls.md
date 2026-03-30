# Common pitfalls

## Imports

Lets reiterate some of the most important submodules in Pwndbg:

+ `pwndbg/dbg_mod` (also providing `pwndbg.dbg`) - Implements a lightweight debugger abstraction layer. Provides functionality that the underlying debugger is responsible for, like setting a breakpoint or writing to memory.
+ `pwndbg/aglib` - A library that uses `pwndbg/dbg_mod` to provide more complex operations, like operations on memory mappings (`pwndbg/aglib/vmmap.py`), registers (`pwndbg/aglib/regs_mod.py`), disassembly (`pwndbg/aglib/disasm/`) etc.
+ `pwndbg/lib` - Generic functionality that *does not* depend on anything "debugger related", like `pwndbg/lib/cache.py`, `pwndbg/lib/zig.py`, `pwndbg/lib/tempfile.py` etc.
+ `pwndbg/commands/` - Pwndbg commands implementations.

To keep this architecture coherent, maintainable, and prevent import cycles, there are a few things we need to obide by that we see being violated from time to time.

#### pwndbg/lib/ files should only access pwndbg.lib

The `pwndbg/lib/` files must be importable and usable from anywhere at anytime, they must not depend on any debugger state.
Thus, the only Pwndbg code you should be importing in a `pwndbg/lib` file, is another `pwndbg/lib` file. God forbid you do `import pwndbg.aglib` or use `pwndbg.dbg` **anywhere** in such a file (even in a non-top-level, function import).

#### Don't access aglib in pwndbg/dbg_mod/

The `aglib` depends on `dbg_mod`, not the other way around. No `dbg_mod/` file should have a top-level `aglib` import. Further, no `dbg_mod/` file should have an `aglib` import anywhere (even function-level). Currently the second rule is not followed, and stuff works, but lets not make it any worse.

#### Don't access pwndbg/dbg_mod/<debugger\>/ in pwndbg/dbg_mod/\_\_init\_\_.py

The top-level debugger abstraction interface, currently only consisting of the `pwndbg/dbg_mod/__init__.py` file, should never reach into or import debugger-specific code like the `pwndbg/dbg_mod/gdb/` files.

On the other hand, it is **okay** to do it the other way around. In other words, you may access `pwndbg/dbg_mod/__init__.py` from debugger-specific code like e.g. `pwndbg/dbg_mod/lldb/hooks.py`.

#### Don't import commands

When a command is written, it is written with the user in mind and all that entails. This means appropriate error handling, message printing etc. A `pwndbg/command/` file has access to every submodule in Pwndbg. As such, it is **not** made to be used as an API for some other command/functionality. If there exists a command which you want to use as API, refactor it into an `aglib/` file, make sure there are no `print`s, make sure that it returns an error instead of silently eating it when appropriate etc.

Doing it this way prevents "fun" surprises, makes the code more maintanable, makes the dependancy graph cleaner and as such prevents import cycles.

#### `from pwndbg.aglib import arch` doesn't work

If you look at `pwndbg/aglib/__init__.py` you will see that `arch` is a None-initialized object and gets swapped out at runtime depending on which architecture we are debugging. As such, to get the correct information about the current architecture you must always do `aglib.arch.whatever()`.

#### `from pwndbg.aglib import regs` doesn't work

If you look at `pwndbg/aglib/__init__.py` you will see that `regs` is a None-initialized object and gets swapped out during initialization. Doing `from pwndbg.aglib import regs` binds `regs` to `None`. Instead always access it via `aglib.regs` like: `aglib.regs.whatever()`.

#### No `module` magic

If you think you need a `class module`, you don't. Any amount of convenience you gain by that is dwarfed by the pain you bring to readability, maintainability, type system processing, LSP analysis etc.

The same goes for
```python
module = sys.modules[__name__]
module.my_cool_thing = 42
```
. This is bad. Don't do this.

#### Don't name the object the same as the file

The `pwndbg/dbg_mod/` folder used to be named `pwndbg/dbg/`, and had a singleton object also called `dbg` defined in `pwndbg/dbg/__init__.py`. `pwndbg/__init__.py` used to have this:
```python
from pwndbg import dbg as dbg_mod
from pwndbg.dbg import dbg as dbg
```
Don't do this. It inhibits readability, causes confusion on what is a submodule and what is an object when importing, messes with type analysis and LSP operations. If you can't think of an original name for your object, name your file `objname_mod.py`. It is a recognizable idiom in the codebase.

See https://github.com/pwndbg/pwndbg/pull/3492 for more info.

#### Don't `import x as y`

In order to keep the code more readable, we should reach for consistency throughout the codebase. Renaming imports in a non-conventional way hurts readability. To provide an example, some files in the codebase do `import pwndbg.color.memory as M` while some do `import pwndbg.color.message as M`. Fun! Prefer to use:
```python
import pwndbg.aglib as aglib
import pwndbg.aglib.memory as memory
import pwndbg.color as color
import pwndbg.color.message as message
import pwndbg.color.memory as mem_color
import pwndbg.color.context as ctx_color
```

#### Try not to touch `pwndbg/gdblib/`

We want to refactor everything from `pwndbg/gdblib/` into `pwndbg/dbg_mod/gdb/`. So if you're writing code into `gdblib` or
writing code that uses `gdblib` you must have a really good reason to do so.

#### Imports have side-effects

A large amount of imports in the codebase have side-effects. Some/most are not immediately visible, but it is good to keep in mind. For instance the `@pwndbg.commands.Command` and `@pwndbg.lib.cache.cache_until` decorators and the `pwndbg.config.add_param` function all modify non-local state.

#### mypy is complaining about an unecessary import

If your import is truly unecessary then remove it. If you are performing an import because you wish to trigger the side-effects of that import, you can use this syntax to appease mypy:
```python
from pwndbg.dbg_mod.gdb import debug_sym as debug_sym
```

#### Import what you use!

We have some places in the codebase that do stuff like `import pwndbg` and then use `pwndbg.aglib.nearpc.whatever()`. This will work at runtime because the `pwndbg.aglib.nearpc` module does exist, but you should import it explicitly with `import pwndbg.aglib.nearpc`! This makes it easier for readers to figure out inter-file dependancies and makes it possible for static checkers to resolve correct types. If after importing at the top you get a circular import error, this means it's time to refactor!

#### Import at the top!

If you need to peform a function-level import this is likely an omen that the code deserves a refactor. So import at the top of the file! There are even places in the code where function-level imports are used but they could easily be moved to top-level imports with no other changes; do not contribute to this confusion!

There are some exceptions to this rule of course, such as `dbg.setup()`, `aglib.load_aglib()`, `commands.load_commands()` and `gdblib.load_gdblib()`. But these are rare and have a clear intention.

## Linting and typing

Currently we run a relatively strict lint on PRs. First `./lint.sh` needs to pass, further, you must not increase the number of `mypy --strict` errors as compared to the `dev` branch (see `.github/workflows/lint.sh`).

This is done to make sure the codebase does not deteriorate over time. Type errors are often indicative of real bugs.

The easiest way to debug any typing issues is to have a type checker running in your python editor / IDE. It does not necessarily have to be mypy (pyright, ty, pyrefly etc. will also work as they all report similar issues), but mypy will be used as the source of truth for the purposes of our CI. If you are using mypy with your editor, make sure you have passed it the `--strict` flag.

#### mypy and mypy --strict disagree!

First of all, one might question why we run both `mypy` and `mypy --strict` over the codebase, and not just `mypy --strict`. This is done to prevent code changes that fix "trivial" type fixes, but introduce severe type issues. In these cases, our `mypy --strict` CI will pass because the total number of type issues has been reduced, but the `mypy` run will still catch the problem.

This can however be troublesome in some cases. For instance, there are (rare) situations where you can reasonably add a `# type: ignore[<something>]` comment to a line of code (one such situation is when interfacing with pyelftools which includes a py.typed marker even though the codebase has no types (https://github.com/eliben/pyelftools/pull/611)). It can happen then, that `mypy --strict` requires such a comment, but that `mypy` complains about an "unused type: ignore".

To fix this, ideally, you fix the source of the typing error and remove the comment. This is most often possible and will appease both `mypy` and `mypy --strict`. If this is not possible, you can often get around the issue by using `cast` as seen here: https://github.com/pwndbg/pwndbg/blob/a35bf70366645b7bbd1359aee6e0caf0958aca87/pwndbg/integration/__init__.py#L182 . If that is also not possible due to the nature of the issue, tell us, and we will figure out what to do together.

