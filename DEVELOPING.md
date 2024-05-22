- [Development Basics](#development-basics)
  - [Environment setup](#environment-setup)
  - [Testing](#testing)
  - [Linting](#linting)
  - [Minimum Supported Versions](#minimum-supported-versions)
- [Adding a Command](#adding-a-command)
- [Adding a Configuration Option](#adding-a-configuration-option)
  - [Configuration Docstrings](#configuration-docstrings)
  - [Triggers](#triggers)
- [Porting public tools](#porting-public-tools)
- [Random developer notes](#random-developer-notes)

# Development Basics
## Environment setup

After installing `pwndbg` by running `setup.sh`, you additionally need to run `./setup-dev.sh` to install the necessary development dependencies.

If you would like to use Docker, you can create a Docker image with everything already installed for you. To do this, run the following command:
```bash
docker run -it --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v `pwd`:/pwndbg pwndbg bash
```

If you'd like to use `docker compose`, you can run
```bash
docker compose run -i main
```

## Testing

It's highly recommended you write a new test or update an existing test whenever adding new functionality to `pwndbg`.

Tests are located in [`tests/gdb-tests`](tests/gdb-tests). `tests/unit-tests` also exists, but the unit testing framework is not complete and so it should not be used.

To run the tests, run [`./tests.sh`](./tests.sh). You can filter the tests to run by providing an argument to the script, such as `./tests.sh heap`, which will only run tests that contain "heap" in the name. You can also drop into the PDB debugger when a test fails with `./tests.sh --pdb`.

Our tests are written using [`pytest`](https://docs.pytest.org/en/latest/). It uses some magic so that Python's `assert` can be used for asserting things in tests and it injects dependencies which are called fixtures, into test functions. These fixtures are defined in [`tests/conftest.py`](tests/conftest.py).

We can take a look at [`tests/gdb-tests/tests/test_hexdump.py`](tests/gdb-tests/tests/test_hexdump.py) for an example of a simple test. Looking at a simplified version of the top-level code, we have this:
```python
import gdb
import tests

BINARY = tests.binaries.get("reference-binary.out")
```

Since these tests run inside GDB, we can import the `gdb` Python library. We also import the `tests` module, which makes it easy to get the path to the test binaries located in [`tests/gdb-tests/tests/binaries`](tests/gdb-tests/tests/binaries). You should be able to reuse the binaries in this folder for most tests, but if not feel free to add a new one.

Here's a small snippet of the actual test:
```python
def test_hexdump(start_binary):
    start_binary(BINARY)
    pwndbg.gdblib.config.hexdump_group_width = -1

    gdb.execute("set hexdump-byte-separator")
    stack_addr = pwndbg.gdblib.regs.rsp - 0x100
```

`pytest` will run any function that starts with `test_` as a new test, so there is no need to register your new test anywhere. The `start_binary` argument is a function that will run the binary you give it, and it will set some common options before starting the binary. Using `start_binary` is recommended if you don't need any additional customization to GDB settings before starting the binary, but if you do it's fine to not use it.

Note that in the test, we can access `pwndbg` library code like `pwndbg.gdblib.regs.rsp` as well as execute GDB commands with `gdb.execute()`.

## Linting

The `lint.sh` script runs `isort`, `black`, `ruff`, `shfmt`, and `vermin`. `isort` and `black` are able to automatically fix any issues they detect, and you can enable this by running `./lint.sh -f`. You can find the configuration files for these tools in `setup.cfg` and `pyproject.toml`.

When submitting a PR, the CI job defined in `.github/workflows/lint.yml` will verify that running `./lint.sh` succeeds, otherwise the job will fail and we won't be able to merge your PR.

You can optionally set the contents of `.git/hooks/pre-push` to the following if you would like `lint.sh` to automatically be run before every push:
```bash
#!/bin/sh

./lint.sh || exit 1
```

## Minimum Supported Versions

Our goal is to fully support all Ubuntu LTS releases that have not reach end-of-life, with support for other platforms on a best-effort basis. Currently that means all code should work on Ubuntu 18.04, 20.04, and 22.04 with GDB 8.1 and later. This means that the minimum supported Python version is 3.6.9, and we cannot use any newer Python features unless those features are backported to this minimum version.

Note that while all code should run without errors on these supported LTS versions, it's fine if older versions don't support all of the features of newer versions, as long as this is handled correctly and this information is shown to the user. For example, we may make use of some GDB APIs in newer versions that we aren't able to provide alternative implementations for in older versions, and so in these cases we should inform the user that the functionality can't be provided due to the version of GDB.

The `lint.sh` script described in the previous section runs [`vermin`](https://github.com/netromdk/vermin) to ensure that our code does not use any features that aren't supported on Python 3.6.

# Adding a Command

Create a new Python file in `pwndbg/commands/my_command.py`, replacing `my_command` with a reasonable name for the command. The most basic command looks like this:

```python
import argparse

import pwndbg.commands

parser = argparse.ArgumentParser(description="Command description.")
parser.add_argument("arg", type=str, help="An example argument.")


@pwndbg.commands.ArgparsedCommand(parser)
def my_command(arg: str) -> None:
    """Print the argument"""
    print(f"Argument is {arg}")
```

In addition, you need to import this file in the `load_commands` function in `pwndbg/commands/__init__.py`. After this, running `my_command foo` in GDB will print out "Argument is foo".

# Adding a Configuration Option

```python
import pwndbg.gdblib.config

pwndbg.gdblib.config.add_param("config-name", False, "example configuration option")
```

`pwndbg.gdblib.config.config_name` will now refer to the value of the configuration option, and it will default to `False` if not set.

## Configuration Docstrings

TODO: There are many places GDB shows docstrings, and they show up slightly differently in each place, we should give examples of this

* When using `pwndbg.gdblib.config.add_param` to add a new config, there are a few things to keep in mind:
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

* If there is possibility, don't use `gdb.execute` as this requires us to parse the string and so on; there are some cases in which there is no other choice. Most of the time we try to wrap GDB's API to our own/easier API.

* We have our own `pwndbg.config.Parameter` (which extends `gdb.Parameter`) - all of our parameters can be seen using `config` or `theme` commands.

* The dashboard/display/context we are displaying is done by `pwndbg/commands/context.py` which is invoked through GDB's prompt hook (which we defined in `pwndbg/prompt.py` as `prompt_hook_on_stop`).

* We change a bit GDB settings - this can be seen in `pwndbg/__init__.py` - there are also imports for all pwndbg submodules

* We have a wrapper for GDB's events in `pwndbg/events.py` - thx to that we can e.g. invoke something based upon some event

* We have a caching mechanism (["memoization"](https://en.wikipedia.org/wiki/Memoization)) which we use through Python's decorators - those are defined in `pwndbg/lib/cache.py` - just check its usages

* To block a function before the first prompt was displayed use the `pwndbg.decorators.only_after_first_prompt` decorator.

* Memory accesses should be done through `pwndbg/memory.py` functions

* Process properties can be retrieved thx to `pwndbg/gdblib/proc.py` - e.g. using `pwndbg.gdblib.proc.pid` will give us current process pid

* We have a wrapper for handling exceptions that are thrown by commands - defined in `pwndbg/exception.py` - current approach seems to work fine - by using `set exception-verbose on` - we get a stacktrace. If we want to debug stuff we can always do `set exception-debugger on`.

* Some of pwndbg's functionality - e.g. memory fetching - require us to have an instance of proper `gdb.Type` - the problem with that is that there is no way to define our own types - we have to ask gdb if it detected particular type in this particular binary (that sucks). We do it in `pwndbg/typeinfo.py` and it works most of the time. The known bug with that is that it might not work properly for Golang binaries compiled with debugging symbols.

* If you want to use `gdb.parse_and_eval("a_function_name()")` or something similar that call a function, please remember this might cause another thread to continue execution without `set scheduler-locking on`. If you didn't expect that, you should use `parse_and_eval_with_scheduler_lock` from `pwndbg.gdblib.scheduler` instead.





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

Everytime the inferior process stops (and when the `disasm` context section is displayed), we display the next handful of assembly instructions in the dashboard so the user can understand where the process is headed. The exact amount is determined by the `context-code-lines` setting.

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

```
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
- The folder `pwndbg/disasm` contains the code for enhancement. It follows an object-oriented model, with `arch.py` implementing the parent class with shared functionality, and the per-architecture implementations are implemented as subclasses in their own files.
- `pwndbg/gdblib/nearpc.py` is responsible for getting the list of enhanced PwndbgInstruction objects and converting them to the output seen in the 'disasm' view of the dashboard.
