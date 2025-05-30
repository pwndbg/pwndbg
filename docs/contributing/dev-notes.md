# Developer Notes

## Random developer notes

Feel free to update the list below!

* If you want to play with Pwndbg functions under GDB, you can always use GDB's `pi` which launches python interpreter or just `py <some python line>`.

* If you want to do the same in LLDB, you should type `lldb`, followed by `script`, which brings up an interactive Python REPL. Don't forget to `import pwndbg`!

* Do not access debugger-specific functionality - eg. anything that uses the `gdb`, `lldb`, or `gdblib` modules - from outside the proper module in `pwndbg.dbg`.

* Use `aglib` instead of `gdblib`, as the latter is [in the process of being removed](https://github.com/pwndbg/pwndbg/issues/2489). Both modules should have nearly identical interfaces, so doing this should be a matter of typing `pwndbg.aglib.X` instead of `pwndbg.gdblib.X`. Ideally, an issue should be opened if there is any functionality present in `gdblib` that's missing from `aglib`.

* We have our own `pwndbg.config.Parameter` - read about it in [Adding a Configuration Option](adding-a-parameter.md).

* The dashboard/display/context we are displaying is done by `pwndbg/commands/context.py` which is invoked through GDB's and LLDB's prompt hook, which are defined, respectively, in `pwndbg/gdblib/prompt.py` as `prompt_hook_on_stop`, and in `pwndb/dbg/lldb/hooks.py` as `prompt_hook`.

* We change a bit GDB settings - this can be seen in `pwndbg/dbg/gdb.py` under `GDB.setup` - there are also imports for all Pwndbg submodules.

* Pwndbg has its own event system, and thanks to it we can set up code to be invoked in response to them. The event types and the conditions in which they occurr are defined and documented in the `EventType` enum, and functions are registered to be called on events with the `@pwndbg.dbg.event_handler` decorator. Both the enum and the decorator are documented in `pwndbg/dbg/__init__.py`.

* We have a caching mechanism (["memoization"](https://en.wikipedia.org/wiki/Memoization)) which we use through Python's decorators - those are defined in `pwndbg/lib/cache.py` - just check its usages

* To block a function before the first prompt was displayed use the `pwndbg.decorators.only_after_first_prompt` decorator.

* Memory accesses should be done through `pwndbg/aglib/memory.py` functions.

* Process properties can be retrieved thanks to `pwndbg/aglib/proc.py` - e.g. using `pwndbg.aglib.proc.pid` will give us current process pid


* We have a wrapper for handling exceptions that are thrown by commands - defined in `pwndbg/exception.py` - current approach seems to work fine - by using `set exception-verbose on` - we get a stacktrace. If we want to debug stuff we can always do `set exception-debugger on`.

* Some of Pwndbg's functionality require us to have an instance of `pwndbg.dbg.Value` - the problem with that is that there is no way to define our own types in either GDB or LLDB - we have to ask the debugger if it detected a particular type in this particular binary (that sucks). We do that in `pwndbg/aglib/typeinfo.py` and it works most of the time. The known bug with that is that it might not work properly for Golang binaries compiled with debugging symbols.

## Support for Multiple Debuggers

Pwndbg is a tool that supports multiple debuggers, and so using debugger-specific functionality
outside of `pwndbg.dbg.X` is generally discouraged, with one imporant caveat, that we will get into
later. When adding code to Pwndbg, one must be careful with the functionality being used.

### The Debugger API

Our support for multiple debuggers is primarily achieved through use of the Debugger API, found
under `pwndbg/dbg/`, which defines a terse set of debugging primitives that can then be built upon
by the rest of Pwndbg. It comprises two parts: the interface, and the implementations. The interface
contains the abstract classes and the types that lay out the "shape" of the functionality that may
be used by the rest of Pwndbg, and the implementations, well, _implement_ the interface on top of each
supported debugger.

As a matter of clarity, it makes sense to think of the Debugger API as a debugger-agnostic version
of the `lldb` and `gdb` Python modules. Compared to both modules, it is much closer in spirit to
`lldb` than to `gdb`.

It is important to note that a lot of care must be exercised when adding things to the Debugger API,
as one must always add implementations for all supported debuggers of whatever new functionality is
being added, even if only to properly gate off debuggers in which the functionality is not supported.
Additionally, it is important to keep the Debugger API interfaces as terse as possible in order to
reduce code duplication. As a rule of thumb, if all the implementations of an interface are expected
to share code, that interface is probably better suited for `aglib`, and it should be further broken
down into its primitives, which can then be added to the Debugger API.

Some examples of debugging primitives are memory reads, memory writes, memory map acquisition,
symbol lookup, register reads and writes, and execution frames. These are all things that one can
find in both the GDB and LLDB APIs.

The entry point for the Debugger API is `pwndbg.dbg`, though most process-related methods are accessed
through a `Process` object. Unless you really know what you're doing, you're going to want to use the
objected yielded by `pwndbg.dbg.selected_inferior()` for this.

### `aglib`

Along with the Debugger API, there is also `aglib`, found under `pwndbg/aglib/`, in which lives
functionality that is both too broad for a single command, and that can be shared between multiple
debuggers. Things like QEMU handling, ELF and dynamic section parsing, operating system functionality,
disassembly with capstone, heap analysis, and more, all belong in `aglib`.

In order to facilitate the process of porting Pwndbg to the debugger-agnostic interfaces, and also
because of its historical roots, `aglib` is intended to export the exact same functionality provided
by `gdblib`, but on top of a debugger-agnostic foundation.

If it helps, one may think of `aglib` like a `pwndbglib`. It takes the debugging primitives provided
by the Debugger API and builds the more complex and interesting bits of functionality found in
Pwndbg on top of them.

### Mappings from GDB and LLDB to the Debugger API

Here are some things one may want to do, along with how they can be achieved in the GDB, LLDB, and
Pwndbg Debugger APIs.

=== "GDB"
    Setting a breakpoint at an address:
    ```python
    gdb.Breakpoint("*<address>")
    ```
    Querying for the address of a symbol:
    ```python
    int(gdb.lookup_symbol(<name>).value().address)
    ```
    Setting a watchpoint at an address:
    ```python
    gdb.Breakpoint(f"(char[{<size>}])*{<address>}", gdb.BP_WATCHPOINT)
    ```

=== "LLDB"
    Setting a breakpoint at an address:
    ```python
    lldb.target.BreakpointCreateByAddress(<address>)
    ```
    Querying for the address of a symbol:
    ```python
    lldb.target.FindSymbols(<name>).GetContextAtIndex(0).symbol.GetStartAddress().GetLoadAddress(lldb.target)
    ```
    Setting a watchpoint at an address:
    ```python
    lldb.target.WatchAddress(<address>, <size>, ...)
    ```

=== "Debugger API"
    ```python
    # Fetch a Process object on which we will operate.
    inf = pwndbg.dbg.selected_inferior()
    ```
    Setting a breakpoint at an address:
    ```python
    inf.break_at(BreakpointLocation(<address>))
    ```
    Querying for the address of a symbol:
    ```python
    inf.lookup_symbol(<name>)
    ```
    Setting a watchpoint at an address:
    ```python
    inf.break_at(WatchpointLocation(<address>, <size>))
    ```

### Exception to use of Debugger-agnostic interfaces

Some commands might not make any sense outside the context of a single debugger. For these commands,
it is generally okay to talk to the debugger directly. However, they must be properly marked as
debugger-specific and their loading must be properly gated off behind the correct debugger. They
should ideally be placed in a separate location from the rest of the commands in `pwndbg/commands/`.

## Porting public tools

If porting a public tool to Pwndbg, please make a point of crediting the original author. This can be added to [CREDITS.md](https://github.com/pwndbg/pwndbg/blob/dev/CREDITS.md) noting the original author/inspiration, and linking to the original tool/article. Also please be sure that the license of the original tool is suitable to porting into Pwndbg, such as MIT.

## Minimum Supported Versions

Our goal is to fully support all Ubuntu LTS releases that have not reached end-of-life, with support for other
platforms on a best-effort basis. Currently that means all code should work on Ubuntu 22.04, and 24.04 with GDB
12.1 and later. This means that the minimum supported Python version is 3.10, and we cannot use any newer
Python features unless those features are backported to this minimum version.

Note that while all code should run without errors on these supported LTS versions, it's fine if older versions
don't support all of the features of newer versions, as long as this is handled correctly and this information
is shown to the user. For example, we may make use of some GDB APIs in newer versions that we aren't able to
provide alternative implementations for in older versions, and so in these cases we should inform the user that
the functionality can't be provided due to the version of GDB.

The `lint.sh` script described in the previous section runs [`vermin`](https://github.com/netromdk/vermin) to
ensure that our code does not use any features that aren't supported on Python 3.10.
