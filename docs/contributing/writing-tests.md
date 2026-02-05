# Writing Tests

## Overview

!!! note
    This is written under the assumption you already know how to [run the tests](../contributing/index.md#running-tests).

In Pwndbg we have four types of tests: extensive (mostly x86_64) userspace tests, cross-architecture tests, linux kernel tests
and unit-tests. They are all located in subdirectories of [`./tests`](https://github.com/pwndbg/pwndbg/tree/dev/tests).

The userspace tests encompass most of the Pwndbg testing suite. If your tests do not belong in any of the other
categories, they should go here. We run the same tests under both GDB and LLDB, and thus they use an abstraction layer to
perform stuff like "set a breakpoint" or "continue execution". They are located in the [`./tests/library/dbg`](https://github.com/pwndbg/pwndbg/tree/dev/tests/library/dbg) directory and can be run with `./tests.sh --driver gdb --group dbg` and `./tests.sh -d lldb -g dbg`.

These tests are also run on an aarch64 host in the Pwndbg CI, and most of them should be architecture agnostic. There are also
gdb tests which you can run with `./tests.sh --driver gdb --group gdb`, located in the [`./tests/library/gdb`](https://github.com/pwndbg/pwndbg/tree/dev/tests/library/gdb) folder. These are mostly tests which have simply not yet been ported over to the new `./tests/library/dbg` system. We would
ideally like to reduce the `gdb/` tests to only a minimal set which test truly gdb-only features. If you encounter a function which
is implemented equivalently in both `gdb/` and `dbg/`, you should remove it from the `gdb/` file, there is no need to run the same
test twice (duplicates were left during the porting process, to ensure it goes smoothly).

The cross-architecture tests are run using qemu-user emulation. They test architecture-specific logic and
are located in the [`./tests/library/qemu_user`](https://github.com/pwndbg/pwndbg/tree/dev/tests/library/qemu_user)
directory. They can be run with `./tests.sh -d gdb -g cross-arch-user`.

The linux kernel tests are run using qemu-system emulation. They are located in the
[`./tests/library/qemu_system`](https://github.com/pwndbg/pwndbg/tree/dev/tests/library/qemu_system)
directory and run for a variety kernel configurations and architectures.

The unit tests are not run from within a debugger, but rather directly with pytest. They are located
in the [`./tests/unit_tests/`](https://github.com/pwndbg/pwndbg/tree/dev/tests/unit_tests)
directory.

Here are the options supported by `./tests.sh` which you can get by running `./tests.sh --help`.
```
usage: tests.py [-h] -g {gdb,lldb,dbg,cross-arch-user} -d {gdb,lldb} [-p] [-c] [-v] [-s] [--nix] [--collect-only] [--clean] [test_name_filter]

Run tests.

positional arguments:
  test_name_filter      run only tests that match the regex

options:
  -h, --help            show this help message and exit
  -g {gdb,lldb,dbg,cross-arch-user}, --group {gdb,lldb,dbg,cross-arch-user}
  -d {gdb,lldb}, --driver {gdb,lldb}
  -p, --pdb             enable pdb (Python debugger) post mortem debugger on failed tests
  -c, --cov             enable codecov
  -v, --verbose         display all test output instead of just failing test output
  -s, --serial          run tests one at a time instead of in parallel
  --nix                 run tests using built for nix environment
  --collect-only        only show the output of test collection, don't run any tests
  --clean               clean (delete) all the test binaries
```
## Writing tests

Each test is a Python function that runs inside of an isolated debugger session which is dispatched through the [`@pwndbg_test`](https://github.com/pwndbg/pwndbg/tree/dev/tests/library/dbg/tests/__init__.py) decorator. The cross-arch-user QEMU tests are passed an appropriate starting function using [`pytest`](https://docs.pytest.org/en/latest/) [`fixtures`](https://github.com/pwndbg/pwndbg/tree/dev/tests/library/qemu_user/conftest.py). Each test runs some commands and uses Python `assert` statements to verify correctness. We can access Pwndbg library code like `pwndbg.aglib.regs.sp`, execute common debugger actions through the test control API like `await ctrl.cont()`, or use the same to execute Pwndbg commands e.g. `await ctrl.execute_and_capture("telescope")`. Do not `ctrl.execute()` debugger-specific commands! - add a new function to the `Controller` in [`tests/host/__init__.py`](https://github.com/pwndbg/pwndbg/blob/dev/tests/host/__init__.py) if you need it.

We can take a look at [`tests/library/dbg/tests/test_mallocng.py`](https://github.com/pwndbg/pwndbg/tree/dev/tests/library/dbg/tests/test_mallocng.py)
as an example test file.

```python
from __future__ import annotations

import re
from pathlib import Path

import pytest

from ....host import Controller
from . import break_at_sym
from . import get_binary
from . import launch_to
from . import pwndbg_test

HEAP_MALLOCNG_DYN = get_binary("heap_musl_dyn.native.out")
HEAP_MALLOCNG_STATIC = get_binary("heap_musl_static.native.out")

# Userland only
re_addr = r"0x[0-9a-fA-F]{1,12}"
```

We import some convenience functions provided to us by [`tests/library/dbg/tests/__init__.py`](https://github.com/pwndbg/pwndbg/tree/dev/tests/library/dbg/tests/__init__.py) and the [`Controller`](https://github.com/pwndbg/pwndbg/blob/dev/tests/host/__init__.py) class which implements the debugger-agnostic control. The `get_binary` function returns a [`pathlib.Path`](https://docs.python.org/3/library/pathlib.html#pathlib.Path) from the [`binaries`](https://github.com/pwndbg/pwndbg/tree/dev/tests/binaries/host) directory. You should be able to reuse the binaries in this folder for most tests, but if not feel free to add a new one.

Here's a function form the file:

```python
@pwndbg_test
@pytest.mark.parametrize(
    "binary", [HEAP_MALLOCNG_DYN, HEAP_MALLOCNG_STATIC], ids=["dynamic", "static"]
)
async def test_mallocng_slot_start(ctrl: Controller, binary: Path):
    import pwndbg.color as color

    await launch_to(ctrl, binary, "break_here")
    await ctrl.finish()

    # Check ng-slots is the same as ng-slotu when p == start
    # and that they aren't the same when p != start.

    slotu_buffer2_out = color.strip(await ctrl.execute_and_capture("ng-slotu buffer2"))
    slots_buffer2_out = color.strip(await ctrl.execute_and_capture("ng-slots buffer2"))
    slotu_buffer5_out = color.strip(await ctrl.execute_and_capture("ng-slotu buffer5"))
    slots_buffer5_out = color.strip(await ctrl.execute_and_capture("ng-slots buffer5"))

    assert "not cyclic" in slotu_buffer2_out
    assert slotu_buffer2_out == slots_buffer2_out

    if binary == HEAP_MALLOCNG_STATIC:
        assert "not cyclic" not in slotu_buffer5_out
        # Doing `ng-slots buffer5` will give you garbage since buffer5 is not
        # a valid slot start.
        assert slotu_buffer5_out != slots_buffer5_out
```

`pytest` will run any function that starts with `test_` as a new test. We decorate our test function with `@pwndbg_test` as explained before. Furthermore, as we want to run this specific function both for the dynamically compiled binary and the statically compiled binary, we decorate it with `@pytest.mark.parametrize` as well. We put all pwndbg imports inside the function itself - putting them at the top of the test file is currently not supported. We use `launch_to` to run the binary until our `break_here` function, and then exit from that helper function back to main with `ctrl.finish()`. Finally, we assert on the output of `ctrl.execute_and_capture` to check whether the output of our command is as expected.

Here is what [`heap_musl.native.c`](https://github.com/pwndbg/pwndbg/blob/dev/tests/binaries/host/heap_musl.native.c) looks like:

```c
#include <stdlib.h>
#include <string.h>

void break_here() {};

int main () {
  char* buffer1 = malloc(0x50);
  char* buffer2 = malloc(0x50);
  char* buffer3 = malloc(0x50);
  char* buffer4 = malloc(0x211);
  char* buffer5 = malloc(0x211);

  break_here();

  memset(buffer1, 0xA, 0x50);
  memset(buffer2, 0xB, 0x50);
  // ....
}
```

## QEMU Tests

To test architecture specific features, like disassembly annotations, we use emulate the appropriate architecure with qemu-user and attach to its debug port. These tests are located in [`tests/library/qemu_user/tests`](https://github.com/pwndbg/pwndbg/tree/dev/tests/library/qemu_user/tests). They are currently `gdb-only` and thus follow the same format as the `gdb/` tests. They require a Python function with a Pytest fixture name as the parameter (it matches based on the name). You call the argument/fixture to start debugging a binary. The `qemu_assembly_run` fixture takes in a Python string of assembly code, compiles it in the appropriate architecture, and runs it - no need to create an external file or edit a Makefile.
