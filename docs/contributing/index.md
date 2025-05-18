- [Development Basics](#development-basics)
  - [Install from source GDB](#install-from-source-gdb)
  - [Install from source LLDB](#install-from-source-lldb)
  - [Environment setup](#environment-setup)
  - [Development using Nix](#development-using-nix)
  - [Testing](#testing)
  - [Writing Tests](#writing-tests)
  - [QEMU Tests](#qemu-tests)
  - [Kernel Tests](#kernel-tests)
    - [Testing Under Nix](#testing-under-nix)
  - [Linting](#linting)
  - [Minimum Supported Versions](#minimum-supported-versions)
- [Adding a Command](#adding-a-command)
- [Adding a Configuration Option](#adding-a-configuration-option)
  - [Configuration Docstrings](#configuration-docstrings)
  - [Triggers](#triggers)
- [Porting public tools](#porting-public-tools)
- [Random developer notes](#random-developer-notes)
- [Annotations](#annotations)
  - [Enhancing](#enhancing)
  - [When to use emulation / reasoning about process state](#when-to-use-emulation--reasoning-about-process-state)
  - [What if the emulator fails?](#what-if-the-emulator-fails)
  - [Caching annotations](#caching-annotations)
  - [Other random annotation details](#other-random-annotation-details)
  - [Adding or fixing annotations](#adding-or-fixing-annotations)
  - [Bug root cause](#bug-root-cause)
  - [Creating small cross-architecture programs](#creating-small-cross-architecture-programs)

## Contributing Basics

Thank you for your interest in contributing to pwndbg!

Note that while it is recommended that your pull request (PR) links to an issue (which can be used for discussing the bug / feature), you do not need to be assigned to it - just create the PR and it will be reviewed.

To start, [install pwndbg from source and set it up for development](1-setup-pwndbg-dev.md).
For common tasks see:

+ [Adding a command](adding-a-command.md)
+ [Adding a configuration option](adding-a-parameter.md)
+ [Improving annotations](improving-annotations.md)

Regardless of the contents of your PR, you will need to [lint](#linting) and [test](#testing) your code. It is also likely you will need to [update the documentation](#TODO).

## Linting

The `lint.sh` script runs isort, ruff, shfmt, and vermin. isort and (mostly) ruff are able to automatically fix any issues they detect, and you can enable this by running `./lint.sh -f`. You can find the configuration files for these tools in `pyproject.toml` or by checking the arguments passed inside `lint.sh`.

When submitting a PR, the CI job defined in `.github/workflows/lint.yml` will verify that running `./lint.sh` succeeds, otherwise the job will fail and we won't be able to merge your PR.

You can optionally set the contents of `.git/hooks/pre-push` to the following if you would like `lint.sh` to automatically be run before every push:
```{.bash .copy}
#!/bin/sh

./lint.sh || exit 1
```

## Testing

It's highly recommended you write a new test or update an existing test whenever adding new functionality to pwndbg.

We have four types of tests: `gdb-tests`,`qemu-tests`, `unit-tests`, and Linux kernel tests, which are all located in subdirectories of [`tests`](https://github.com/pwndbg/pwndbg/tree/dev/tests).

`gdb-tests` refers to our x86 tests, which are located [`tests/gdb-tests`](tests/gdb-tests/).

To run these tests, run [`./tests.sh`](./tests.sh). You can filter the tests to run by providing an argument to the script, such as `./tests.sh heap`, which will only run tests that contain "heap" in the name. You can also drop into the PDB debugger when a test fails with `./tests.sh --pdb`.

To invoke cross-architecture tests, use `./qemu-tests.sh`, and to run unit tests, use `./unit-tests.sh`

To run the tests in the same environment as the testing CI/CD, you can use the following Docker command.

```sh
# General test suite
docker compose run --rm --build ubuntu24.04-mount ./tests.sh
# Cross-architecture tests
docker compose run --rm --build ubuntu24.04-mount ./qemu-tests.sh
```

This comes in handy particularly for cross-architecture tests because the Docker environment has all the cross-compilers installed. The active `pwndbg` directory is mounted, preventing the need for a full rebuild whenever you update the codebase.

Remove the `-mount` if you want the tests to run from a clean slate (no files are mounted, meaning all binaries are recompiled each time).

## Writing Tests

Each test is a Python function that runs inside of an isolated GDB session.
Using a [`pytest`](https://docs.pytest.org/en/latest/) fixture at the beginning of each test,
GDB will attach to a [`binary`](tests/gdb-tests/conftest.py) or connect to a [`QEMU instance`](tests/qemu-tests/conftest.py).
Each test runs some commands and uses Python `assert` statements to verify correctness.
We can access `pwndbg` library code like `pwndbg.aglib.regs.rsp` as well as execute GDB commands with `gdb.execute()`.

We can take a look at [`tests/gdb-tests/tests/test_symbol.py`](tests/gdb-tests/tests/test_symbol.py) for an example of a
simple test. Looking at a simplified version of the top-level code, we have this:

```python
import gdb
import pwndbg
import tests

BINARY = tests.binaries.get("symbol_1600_and_752.out")
```

Since these tests run inside GDB, we can import the `gdb` Python library. We also import the `tests` module, which makes it easy to get the path to the test binaries located in [`tests/gdb-tests/tests/binaries`](tests/gdb-tests/tests/binaries). You should be able to reuse the binaries in this folder for most tests, but if not feel free to add a new one.

Here's a small snippet of the actual test:

```python
def test_hexdump(start_binary):
    start_binary(BINARY)
    pwndbg.config.hexdump_group_width.value = -1

    gdb.execute("set hexdump-byte-separator")
    stack_addr = pwndbg.aglib.regs.rsp - 0x100
```

`pytest` will run any function that starts with `test_` as a new test, so there is no need to register your new test anywhere. The `start_binary` argument is a function that will run the binary you give it, and it will set some common options before starting the binary. Using `start_binary` is recommended if you don't need any additional customization to GDB settings before starting the binary, but if you do it's fine to not use it.

## QEMU Tests

Our `gdb-tests` run in x86. To debug other architectures, we use QEMU for emulation, and attach to its debug port. These tests are located in [`tests/qemu-tests/tests/user`](tests/qemu-tests/tests/user). Test creation is identical to our x86 tests - create a Python function with a Pytest fixture name as the parameter (it matches based on the name), and call the argument to start debugging a binary. The `qemu_assembly_run` fixture takes in a Python string of assembly code, compiles it in the appropriate architecture, and runs it - no need to create an external file or edit a Makefile.

## Kernel Tests

We use `qemu-system` for full system level emulation for our Linux kernel tests. These are located in [`tests/qemu-tests/tests/system`](tests/qemu-tests/tests/system). The tests will run for a variety kernel configurations and architectures.

### Testing Under Nix

You will need to build a nix-compatible `gdbinit.py` file, which you can do with `nix build .#pwndbg-dev`. Then simply
run the test by adding the `--nix` flag:

```bash
./tests.sh --nix [filter]
```

## Minimum Supported Versions

Our goal is to fully support all Ubuntu LTS releases that have not reach end-of-life, with support for other platforms on a best-effort basis. Currently that means all code should work on Ubuntu 22.04, and 24.04 with GDB 12.1 and later. This means that the minimum supported Python version is 3.10, and we cannot use any newer Python features unless those features are backported to this minimum version.

Note that while all code should run without errors on these supported LTS versions, it's fine if older versions don't support all of the features of newer versions, as long as this is handled correctly and this information is shown to the user. For example, we may make use of some GDB APIs in newer versions that we aren't able to provide alternative implementations for in older versions, and so in these cases we should inform the user that the functionality can't be provided due to the version of GDB.

The `lint.sh` script described in the previous section runs [`vermin`](https://github.com/netromdk/vermin) to ensure that our code does not use any features that aren't supported on Python 3.10.

## Triggers

TODO: If we want to do something when user changes config/theme - we can do it defining a function and decorating it
with `pwndbg.config.Trigger`.

# Porting public tools

If porting a public tool to pwndbg, please make a point of crediting the original author. This can be added to
[CREDITS.md](./CREDITS.md) noting the original author/inspiration, and linking to the original tool/article. Also please
be sure that the license of the original tool is suitable to porting into pwndbg, such as MIT.

# Random developer notes

Feel free to update the list below!

* If you want to play with pwndbg functions under GDB, you can always use GDB's `pi` which launches python interpreter or just `py <some python line>`.

* If you want to do the same in LLDB, you should type `lldb`, followed by `script`, which brings up an interactive Python REPL. Don't forget to `import pwndbg`!

* Do not access debugger-specific functionality - eg. anything that uses the `gdb`, `lldb`, or `gdblib` modules - from outside the proper module in `pwndbg.dbg`.

* Use `aglib` instead of `gdblib`, as the latter is [in the process of being removed](https://github.com/pwndbg/pwndbg/issues/2489). Both modules should have nearly identical interfaces, so doing this should be a matter of typing `pwndbg.aglib.X` instead of `pwndbg.gdblib.X`. Ideally, an issue should be opened if there is any functionality present in `gdblib` that's missing from `aglib`.

* We have our own `pwndbg.config.Parameter` - all of our parameters can be seen using `config` or `theme` commands.

* The dashboard/display/context we are displaying is done by `pwndbg/commands/context.py` which is invoked through GDB's and LLDB's prompt hook, which are defined, respectively, in `pwndbg/gdblib/prompt.py` as `prompt_hook_on_stop`, and in `pwndb/dbg/lldb/hooks.py` as `prompt_hook`.

* We change a bit GDB settings - this can be seen in `pwndbg/dbg/gdb.py` under `GDB.setup` - there are also imports for all pwndbg submodules.

* Pwndbg has its own event system, and thanks to it we can set up code to be invoked in response to them. The event types and the conditions in which they occurr are defined and documented in the `EventType` enum, and functions are registered to be called on events with the `@pwndbg.dbg.event_handler` decorator. Both the enum and the decorator are documented in `pwndbg/dbg/__init__.py`.

* We have a caching mechanism (["memoization"](https://en.wikipedia.org/wiki/Memoization)) which we use through Python's decorators - those are defined in `pwndbg/lib/cache.py` - just check its usages

* To block a function before the first prompt was displayed use the `pwndbg.decorators.only_after_first_prompt` decorator.

* Memory accesses should be done through `pwndbg/aglib/memory.py` functions.

* Process properties can be retrieved thanks to `pwndbg/aglib/proc.py` - e.g. using `pwndbg.aglib.proc.pid` will give us current process pid


* We have a wrapper for handling exceptions that are thrown by commands - defined in `pwndbg/exception.py` - current approach seems to work fine - by using `set exception-verbose on` - we get a stacktrace. If we want to debug stuff we can always do `set exception-debugger on`.

* Some of pwndbg's functionality require us to have an instance of `pwndbg.dbg.Value` - the problem with that is that there is no way to define our own types in either GDB or LLDB - we have to ask the debugger if it detected a particular type in this particular binary (that sucks). We do that in `pwndbg/aglib/typeinfo.py` and it works most of the time. The known bug with that is that it might not work properly for Golang binaries compiled with debugging symbols.

# Support for Multiple Debuggers

Pwndbg is an tool that supports multiple debuggers, and so using debugger-specific functionality
outside of `pwndbg.dbg.X` is generally discouraged, with one imporant caveat, that we will get into
later. When adding code to Pwndbg, one must be careful with the functionality being used.

## The Debugger API

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

## `aglib`

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

## Mappings from GDB and LLDB to the Debugger API

Here are some things one may want to do, along with how they can be achieved in the LLDB, GDB, and
Pwndbg Debugger APIs.

| Action | GDB/ | LLDB | Debugger API[^1]                                      |
| ------ | --- | ---- |-------------------------------------------------------|
| Setting a breakpoint at an address | `gdb.Breakpoint("*<address>")` | `lldb.target.BreakpointCreateByAddress(<address>)` | `inf.break_at(BreakpointLocation(<address>))`         |
| Querying for the address of a symbol | `int(gdb.lookup_symbol(<name>).value().address)` | `lldb.target.FindSymbols(<name>).GetContextAtIndex(0).symbol.GetStartAddress().GetLoadAddress(lldb.target)` | `inf.lookup_symbol(<name>)`                           |
| Setting a watchpoint at an address | `gdb.Breakpoint(f"(char[{<size>}])*{<address>}", gdb.BP_WATCHPOINT)` | `lldb.target.WatchAddress(<address>, <size>, ...)` | `inf.break_at(WatchpointLocation(<address>, <size>))` |

[^1]: Many functions in the Debugger API are accessed through a `Process` object, which is usually
obtained through `pwndbg.dbg.selected_inferior()`. These are abbreviated `inf` in the table.

## Exception to use of Debugger-agnostic interfaces

Some commands might not make any sense outside the context of a single debugger. For these commands,
it is generally okay to talk to the debugger directly. However, they must be properly marked as
debugger-specific and their loading must be properly gated off behind the correct debugger. They
should ideally be placed in a separate location from the rest of the commands in `pwndbg/commands/`.

## Supported distributions
Pwndbg is supported on Ubuntu 22.04, and 24.04 with GDB 12.1 and later. We do not test
on any older versions of Ubuntu, so `pwndbg` may not work on these versions.
- For Ubuntu 20.04 use the [2024.08.29 release](https://github.com/pwndbg/pwndbg/releases/tag/2024.08.29)
- For Ubuntu 18.04 use the [2023.07.17: ubuntu18.04-final release](https://github.com/pwndbg/pwndbg/releases/tag/2023.07.17)

We may accept pull requests fixing issues in older versions on a case by case basis,
please discuss this with us on [Discord][discord] first. You can also always checkout
an older version of `pwndbg` from around the time the Ubuntu version you're interested
in was still supported by Canonical, or you can attempt to build a newer version of GDB from source.
