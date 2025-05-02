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

# Development Basics

## Install from source GDB
Installation from source is straightforward:
```shell
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

Pwndbg is supported on Ubuntu 22.04, and 24.04 with GDB 12.1 and later. We do not test
on any older versions of Ubuntu, so `pwndbg` may not work on these versions.
- For Ubuntu 20.04 use the [2024.08.29 release](https://github.com/pwndbg/pwndbg/releases/tag/2024.08.29)
- For Ubuntu 18.04 use the [2023.07.17: ubuntu18.04-final release](https://github.com/pwndbg/pwndbg/releases/tag/2023.07.17)

We may accept pull requests fixing issues in older versions on a case by case basis,
please discuss this with us on [Discord][discord] first. You can also always checkout
an older version of `pwndbg` from around the time the Ubuntu version you're interested
in was still supported by Canonical, or you can attempt to build a newer version of GDB from source.

Other Linux distributions are also supported via `setup.sh`, including:

* Debian-based OSes (via apt-get)
* Fedora and Red Hat (via dnf)
* Clear (via swiped)
* OpenSUSE LEAP (via zypper)
* Arch and Manjaro (via community AUR packages)
* Void (via xbps)
* Gentoo (via emerge)

If you use any Linux distribution other than Ubuntu, we recommend using the [latest available GDB](https://www.gnu.org/software/gdb/download/) built from source. You can build it as:
```
cd <gdb-sources-dir>
mkdir build && cd build
sudo apt install libgmp-dev libmpfr-dev libreadline-dev texinfo  # required by build
../configure --disable-nls --disable-werror --with-system-readline --with-python=`which python3` --with-system-gdbinit=/etc/gdb/gdbinit --enable-targets=all
make -j $(nproc)
```

## Install from source LLDB
```shell
git clone https://github.com/pwndbg/pwndbg
cd pwndbg

apt install -y lldb-19 liblldb-19-dev python3 python3-venv
export PATH=/usr/lib/llvm-19/bin/:$PATH
export LLDB_DEBUGSERVER_PATH=/usr/lib/llvm-19/bin/lldb-server

python3 -m venv -- .venv
./.venv/bin/pip install uv
./.venv/bin/uv sync --extra lldb

./.venv/bin/python3 ./pwndbg-lldb.py
```
This will work only for ubuntu 24.04

## Environment setup

After installing `pwndbg` by running `setup.sh`, you additionally need to run `./setup-dev.sh` to install the necessary development dependencies.

If you would like to use Docker, you can create a Docker image with everything already installed for you. To build and
run the container, run the following commands:

```bash
docker build -t pwndbg .
docker run -it --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v `pwd`:/pwndbg pwndbg bash
```

If you'd like to use `docker compose`, you can run

```bash
docker compose run -i main
```

## Development using Nix

Pwndbg supports development with Nix which installs all the required
development dependencies:

1. Install Nix with [Determinate Nix Installer](https://github.com/DeterminateSystems/nix-installer?tab=readme-ov-file#determinate-nix-installer).

2. Enter the development shell with `nix develop` or automate this with `direnv`.

3. Run local changes with `pwndbg` or `pwndbg-lldb`. Run tests with `./tests.sh`.

## Testing

It's highly recommended you write a new test or update an existing test whenever adding new functionality to `pwndbg`.

We have four types of tests: `gdb-tests`,`qemu-tests`, `unit-tests`, and Linux kernel tests, which are all located in subdirectories of [`tests`](tests).

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

## Linting

The `lint.sh` script runs `isort`, `ruff`, `shfmt`, and `vermin`. `isort` and `ruff` are able to automatically fix any
issues they detect, and you can enable this by running `./lint.sh -f`. You can find the configuration files for these
tools in `pyproject.toml` or by checking the arguments passed inside `lint.sh`.

When submitting a PR, the CI job defined in `.github/workflows/lint.yml` will verify that running `./lint.sh` succeeds, otherwise the job will fail and we won't be able to merge your PR.

You can optionally set the contents of `.git/hooks/pre-push` to the following if you would like `lint.sh` to automatically be run before every push:

```bash
#!/usr/bin/env bash

./lint.sh || exit 1
```

## Minimum Supported Versions

Our goal is to fully support all Ubuntu LTS releases that have not reach end-of-life, with support for other platforms on a best-effort basis. Currently that means all code should work on Ubuntu 22.04, and 24.04 with GDB 12.1 and later. This means that the minimum supported Python version is 3.10, and we cannot use any newer Python features unless those features are backported to this minimum version.

Note that while all code should run without errors on these supported LTS versions, it's fine if older versions don't support all of the features of newer versions, as long as this is handled correctly and this information is shown to the user. For example, we may make use of some GDB APIs in newer versions that we aren't able to provide alternative implementations for in older versions, and so in these cases we should inform the user that the functionality can't be provided due to the version of GDB.

The `lint.sh` script described in the previous section runs [`vermin`](https://github.com/netromdk/vermin) to ensure that our code does not use any features that aren't supported on Python 3.10.

# Adding a Command

Create a new Python file in `pwndbg/commands/my_command.py`, replacing `my_command` with a reasonable name for the command. The most basic command looks like this:

```python
import argparse

import pwndbg.commands

parser = argparse.ArgumentParser(description="Command description.")
parser.add_argument("arg", type=str, help="An example argument.")


@pwndbg.commands.Command(parser)
def my_command(arg: str) -> None:
    """Print the argument"""
    print(f"Argument is {arg}")
```

In addition, you need to import this file in the `load_commands` function in `pwndbg/commands/__init__.py`. After this, running `my_command foo` in GDB or LLDB will print out "Argument is foo".

# Adding a Configuration Option

```python
import pwndbg

pwndbg.config.add_param("config-name", False, "example configuration option")
```

`pwndbg.config.config_name` will now refer to the value of the configuration option, and it will default to `False` if not set.

## Configuration Docstrings (GDB)

TODO: There are many places GDB shows docstrings, and they show up slightly differently in each place, we should give examples of this

* When using `pwndbg.config.add_param` to add a new config, there are a few things to keep in mind:
  * For the `set_show_doc` parameter, it is best to use a noun phrase like "the value of something" to ensure that the output is grammatically correct.
  * For the `help_docstring` parameter, you can use the output of `help set follow-fork-mode` as a guide for formatting the documentation string if the config is an enum type.
  * For the `param_class` parameter
    * See the [documentation](https://sourceware.org/gdb/onlinedocs/gdb/Parameters-In-Python.html) for more information.
    * If you use `gdb.PARAM_ENUM` as `param_class`, you must pass a list of strings to the `enum_sequence` parameter.

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

# Annotations

Alongside the disassembled instructions in the dashboard, Pwndbg also has the ability to display annotations - text that contains relevent information regarding the execution of the instruction. For example, on the x86 `MOV` instruction, we can display the concrete value that gets placed into the destination register. Likewise, we can indicate the results of mathematical operations and memory accesses. The annotation in question is always dependent on the exact instruction being annotated - we handle it in a case-by-case basis.

The main hurdle in providing annotations is determining what each instruction does, getting the relevent CPU registers and memory that are accessed, and then resolving concrete values of the operands. We call the process of determining this information "enhancement", as we enhance the information provided natively by GDB.

The Capstone Engine disassembly framework is used to statically determine information about instructions and their operands. Take the x86 instruction `sub rax, rdx`. Given the raw bytes of the machine instructions, Capstone creates an object that provides an API that, among many things, exposes the names of the operands and the fact that they are both 8-byte wide registers. It provides all the information necessary to describe each operand. It also tells the general 'group' that a instruction belongs to, like if its a JUMP-like instruction, a RET, or a CALL. These groups are architecture agnostic.

However, the Capstone Engine doesn't fill in concrete values that those registers take on. It has no way of knowing the value in `rdx`, nor can it actually read from memory.

To determine the actual values that the operands take on, and to determine the results of executing an instruction, we use the Unicorn Engine, a CPU emulator framework. The emulator has its own internal CPU register set and memory pages that mirror that of the host process, and it can execute instructions to mutate its internal state. Note that the Unicorn Engine cannot execute syscalls - it doesn't have knowledge of a kernel.

We have the ability to single-step the emulator - tell it to execute the instruction at the program counter inside the emulator. After doing so, we can inspect the state of the emulator - read from its registers and memory. The Unicorn Engine itself doesn't expose information regarding what each instruction is doing - what is the instruction (is it an `add`, `mov`, `push`?) and what registers/memory locations is it reading to and writing from? - which is why we use the Capstone engine to statically determine this information.

Using what we know about the instruction based on the Capstone engine - such as that it was a `sub` instruction and `rax` was written to - we query the emulator after stepping in to determine the results of the instruction.

We also read the program counter from the emulator to determine jumps and so we can display the instructions that will actually be executed, as opposed to displaying the instructions that follow consecutively in memory.

## Enhancing

Everytime the inferior process stops (and when the `disasm` context section is displayed), we display the next handful of assembly instructions in the dashboard so the user can understand where the process is headed. The exact amount is determined by the `context-disasm-lines` setting.

We will be enhancing the instruction at the current program counter, as well as all the future instructions that are displayed. The end result of enhancement is that we get a list of `PwndbgInstruction` objects, each encapsulating relevent information regarding the instructions execution.

When the process stops, we instantiate the emulator from scratch. We copy all the registers from the host process into the emulator. For performance purposes, we register a handler to the Unicorn Engine to lazily map memory pages from the host to the emulator when they are accessed (a page fault from within the emulator), instead of immediately copying all the memory from the host to the emulator.

The enhancement is broken into a couple stops:

1. First, we resolve the values of all the operands of the instruction before stepping the emulator. This means we read values from registers and dereference memory depending on the operand type. This gives us the values of operands before the instruction executes.
2. Then, we step the emulator, executing a single instruction.
3. We resolve the values of all operands again, giving us the `after_value` of each operand.
4. Then, we enhance the "condition" field of PwndbgInstructions, where we determine if the instruction is conditional (conditional branch or conditional mov are common) and if the action is taken.
5. We then determine the `next` and `target` fields of PwndbgInstructions. `next` is the address that the program counter will take on after using the GDB command `nexti`, and `target` indicates the target address of branch/jump/PC-changing instructions.
6. With all this information determined, we now effectively have a big switch statement, matching on the instruction type, where we set the `annotation` string value, which is the text that will be printed alongside the instruction in question.

We go through the enhancement process for the instruction at the program counter and then ensuing handful of instructions that are shown in the dashboard.

## When to use emulation / reasoning about process state

When possible, we code aims to use emulation as little as possible. If there is information that can be determined statically or without the emulator, then we try to avoid emulation. This is so we can display annotations even when the Unicorn Engine is disabled. For example, say we come to a stop, and are faced with enhancing the following three instructions in the dashboard:

```asm
1.     lea    rax, [rip + 0xd55]
2. >   mov    rsi, rax      # The host process program counter is here
3.     mov    rax, rsi
```

Instruction #1, the `lea` instruction, is already in the past - we pull our enhanced PwndbgInstruction for it from a cache.

Instruction #2, the first `mov` instruction, is where the host process program counter is at. If we did `stepi` in GDB, this instruction would be executed. In this case, there is two ways we can determine the value that gets written to `rsi`.

1. After stepping the emulator, read from the emulators `rsi` register.
2. Given the context of the instruction, we know the value in `rsi` will come from `rax`. We can just read the `rax` register from the host. This avoids emulation.

The decision on which option to take is implemented in the annotation handler for the specific instruction. When possible, we have a preference for the second option, because it makes the annotations work even when emulation is off.

The reason we could do the second option, in this case, is because we could reason about the process state at the time this instruction would execute. This instruction is about to be executed (`Program PC == instruction.address`). We can safely read from `rax` from the host, knowing that the value we get is the true value it takes on when the instruction will execute. It must - there are no instructions in-between that could have mutated `rax`.

However, this will not be the case while enhancing instruction #3 while we are paused at instruction #2. This instruction is in the future, and without emulation, we cannot safely reason about the operands in question. It is reading from `rsi`, which might be mutated from the current value that `rsi` has in the stopped process (and in this case, we happen to know that it will be mutated). We must use emulation to determine the `before_value` of `rsi` in this case, and can't just read from the host processes register set. This principle applies in general - future instructions must be emulated to be fully annotated. When emulation is disable, the annotations are not as detailed since we can't fully reason about process state for future instructions.

## What if the emulator fails?

It is possible for the emulator to fail to execute an instruction - either due to a restrictions in the engine itself, or the instruction inside segfaults and cannot continue. If the Unicorn Engine fails, there is no real way we can recover. When this happens, we simply stop emulating for the current step, and we try again the next time the process stops when we instantiate the emulator from scratch again.

## Caching annotations

When we are stepping through the emulator, we want to remember the annotations of the past couple instructions. We don't want to `nexti`, and suddenly have the annotation of the previously executed instruction deleted. At the same time, we also never want stale annotations that might result from coming back to point in the program to which we have stepped before, such as the middle of a loop via a breakpoint.

New annotations are only created when the process stops, and we create annotations for next handful of instructions to be executed. If we `continue` in GDB and stop at a breakpoint, we don't want annotations to appear behind the PC that are from a previous time we were near the location in question. To avoid stale annotations while still remembering them when stepping, we have a simple caching method:

While we are doing our enhancement, we create a list containing the addresses of the future instructions that are displayed.

For example, say we have the following instructions with the first number being the memory address:

```gdb
   0x555555556259 <main+553>    lea    rax, [rsp + 0x90]
   0x555555556261 <main+561>    mov    edi, 1                          EDI => 1
   0x555555556266 <main+566>    mov    rsi, rax
   0x555555556269 <main+569>    mov    qword ptr [rsp + 0x78], rax
   0x55555555626e <main+574>    call   qword ptr [rip + 0x6d6c]    <fstat64>

 ► 0x555555556274 <main+580>    mov    edx, 5                  EDX => 5
   0x555555556279 <main+585>    lea    rsi, [rip + 0x3f30]     RSI => 0x55555555a1b0 ◂— 'standard output'
   0x555555556280 <main+592>    test   eax, eax
   0x555555556282 <main+594>    js     main+3784                   <main+3784>

   0x555555556288 <main+600>    mov    rsi, qword ptr [rsp + 0xc8]
   0x555555556290 <main+608>    mov    edi, dword ptr [rsp + 0xa8]
```

In this case, our `next_addresses_cache` would be `[0x555555556279, 0x555555556280, 0x555555556282, 0x555555556288, 0x555555556290]`.

Then, the next time our program comes to a stop (after using `si`, `n`, or any GDB command that continues the process), we immediately check if the current program counter is in this list. If it is, then we can infer that the annotations are still valid, as the program has only executed a couple instructions. In all other cases, we delete our cache of annotated instructions.

We might think "why not just check if it's the next address - 0x555555556279 in this case? Why a list of the next couple addresses?". This is because when source code is available, `step` and `next` often skip a couple instructions. It would be jarring to remove the annotations in this case. Likewise, this method has the added benefit that if we stop somewhere, and there happens to be a breakpoint only a couple instructions in front of us that we `continue` to, then previous couple annotations won't be wiped.

## Other random annotation details

- We don't emulate through CALL instructions. This is because the function might be very long.
- We resolve symbols during the enhancement stage for operand values.
- The folder [`pwndbg/aglib/disasm`](pwndbg/aglib/disasm) contains the code for enhancement. It follows an object-oriented model, with `arch.py` implementing the parent class with shared functionality, and the per-architecture implementations are implemented as subclasses in their own files.
- `pwndbg/aglib/nearpc.py` is responsible for getting the list of enhanced PwndbgInstruction objects and converting them to the output seen in the 'disasm' view of the dashboard.

## Adding or fixing annotations

We annotate on an instruction-by-instruction basis. Effectively, imagine a giant `switch` statement that selects the correct handler to create an annotation based on the specific instruction. Many instruction types can be grouped and annotated using the same logic, such as `load`, `store`, and `arithmetic` instructions.

See [`pwndbg/aglib/disasm/aarch64.py`](pwndbg/aglib/disasm/aarch64.py) as an example. We define sets that group instructions using the unique Capstone ID for each instruction, and inside the constructor of `DisassemblyAssistant` we have a mapping of instructions to a specific handler. The `_set_annotation_string` function will match the instruction to the correct handler, which set the `instruction.annotation` field.

If there is a bug in an annotation, the first order of business is finding its annotation handler. To track down where we are handling the instruction, you can search for its Capstone constant. For example, the RISC-V store byte instruction, `sb`, is represented as the Capstone constant `RISCV_INS_SB`. Or, if you are looking for the handler for the AArch64 instruction SUB, you can search the disasm code for `_INS_SUB` to find where we reference the appropriate Capstone constant for the instruction and following the code to the function that ultimately sets the annotation.

If an annotation is causing a crash, is it most likely due to a handler making an incorrect assumption on the number of operands, leading to a `list index out of range` error. One possible source of this is that a given instruction has multiple different disassembly representations. Take the RISC-V `JALR` instruction. It can be represented in 3 ways:

```asm
jalr rs1        # return register is implied as ra, and imm is implied as 0
jalr rs1, imm   # return register is implied as ra
jalr rd, rs1, imm
```

Capstone will expose the most "simplified" one possible, and the underlying list of register operands will change. If the handler doesn't take these different options into account, and rather assumes that `jalr` always has 3 operands, then an index error can occur if the handler accesses `instruction.operands[2]`.

## Bug root cause

When encountering an instruction that is behaving strangely (incorrect annotation, or there is a jump target when one shouldn't exist, or the target is incorrect), there are a couple routine things to check.

1. Use the `dev-dump-instruction` command to print all the enhancement information. With no arguments, it will dump the info from the instruction at the current address. If given an address, it will pull from the instruction cache at the corresponding location.

If the issue is not related to branches, check the operands and the resolved values for registers and memory accesses. Verify that the values are correct - are the resolved memory locations correct? Step past the instruction and use instructions like `telescope` and `regs` to read memory and verify if the claim that the annotation is making is correct. For things like memory operands, you can try to look around the resolved memory location in memory to see the actual value that the instruction dereferenced, and see if the resolved memory location is simply off by a couple bytes.

Example output of dumping a `mov` instruction:

```
mov qword ptr [rsp], rsi at 0x55555555706c (size=4) (arch: x86)
        ID: 460, mov
        Raw asm: mov    qword ptr [rsp], rsi
        New asm: mov    qword ptr [rsp], rsi
        Next: 0x555555557070
        Target: 0x555555557070, Target string=, const=None
        Condition: UNDETERMINED
        Groups: []
        Annotation: [0x7fffffffe000] => 0x7fffffffe248 —▸ 0x7fffffffe618 ◂— '/usr/bin/ls'
        Operands: [['[0x7fffffffe000]': Symbol: None, Before: 0x7fffffffe000, After: 0x7fffffffe000, type=CS_OP_MEM, size=8, access=CS_AC_WRITE]] ['RSI': Symbol: None, Before: 0x7fffffffe248, After: 0x7fffffffe248, type=CS_OP_REG, size=8, access=CS_AC_READ]]]
        Conditional jump: False. Taken: False
        Unconditional jump: False
        Declare unconditional: None
        Can change PC: False
        Syscall:  N/A
        Causes Delay slot: False
        Split: NO_SPLIT
        Call-like: False
```

2. Use the Capstone disassembler to verify the number of operands the instruction groups.

Taken the raw instruction bytes and pass them to `cstool` to see the information that we are working with:

```sh
cstool -d mips 0x0400000c
```

The number of operands may not match the visual appearance. You might also check the instruction groups, and verify that an instruction that we might consider a `call` has the Capstone `call` group. Capstone is not 100% correct in every single case in all architectures, so it's good to verify. Report a bug to Capstone if there appears to be an error, and in the meanwhile we can create a fix in Pwndbg to work around the current behavior.

3. Check the state of the emulator.

Go to [pwndbg/emu/emulator.py](pwndbg/emu/emulator.py) and uncomment the `DEBUG = -1` line. This will enable verbose debug printing. The emulator will print it's current `pc` at every step, and indicate important events, like memory mappings. Likewise, in [pwndbg/aglib/disasm/arch.py](pwndbg/aglib/disasm/arch.py) you can set `DEBUG_ENHANCEMENT = True` to print register accesses to verify they are sane values.

Potential bugs:
- A register is 0 (may also be the source of a Unicorn segfault if used as a memory operand) - often means we are not copying the host processes register into the emulator. By default, we map register by name - if in pwndbg, it's called `rax`, then we find the UC constant named `U.x86_const.UC_X86_REG_RAX`. Sometimes, this default mapping doesn't work, sometimes do to differences in underscores (`FSBASE` vs `FS_BASE`). In these cases, we have to manually add the mapping.
- Unexpected crash - the instruction at hand might require a 'coprocessor', or some information that is unavailable to Unicorn (it's QEMU under the hood).
- Instructions are just no executing - we've seen this in the case of Arm Thumb instructions. There might be some specific API/way to invoke the emulator that is required for a certain processor state.

## Creating small cross-architecture programs

If you are encountering a strange behavior with a certain instruction or scenario in a non-native-architecture program, you can use some great functions from `pwntools` to handle the compilation and debugging. This is a great way to create a small reproducible example to isolate an issue.

The following Python program, when run from inside a `tmux` session, will take some AArch64 assembly, compile it, and run it with GDB attached in a new `tmux` pane. It will search your system for the appropriate cross compiler for the architecture at hand, and run the compiled binary with QEMU.

```python
from pwn import *

context.arch = "aarch64"

AARCH64_GRACEFUL_EXIT = """
mov x0, 0
mov x8, 93
svc 0
"""

out = make_elf_from_assembly(STORE)
# Debug info
print(out)
gdb.debug(out)

pause()
```
