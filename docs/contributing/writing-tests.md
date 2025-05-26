# Writing Tests

## Overview

!!! note
    This is written under the assumption you already know how to [run the tests](../contributing/index.md#running-tests).

In pwndbg we have four types of tests: extensive x86_64 gdb tests, cross-architecture tests, linux kernel tests
and unit-tests. They are all located in subdirectories of [`./tests`](https://github.com/pwndbg/pwndbg/tree/dev/tests).

The x86_64 tests encompass most of the pwndbg testing suite. If your tests do not belong in any of the other
categories, they should go here. Since we do not yet perform testing on lldb, these are run from inside gdb
and are located in the [`./tests/gdb-tests`](https://github.com/pwndbg/pwndbg/tree/dev/tests/gdb-tests/)
directory. They can be run with `./tests.sh -t gdb` (this is the default option).

The cross-architecture tests are run using qemu-user emulation. They test architecture-specific logic and
are located in the [`./tests/qemu-tests/tests/user`](https://github.com/pwndbg/pwndbg/tree/dev/tests/qemu-tests/tests/user)
directory. They can be run with `./tests.sh -t cross-arch` (this is what `./qemu-tests.sh` does).

The linux kernel tests are run using qemu-system emulation. They are located in the [`./tests/qemu-tests/tests/system`](https://github.com/pwndbg/pwndbg/tree/dev/tests/qemu-tests/tests/system)
directory and run for a variety kernel configurations and architectures.

The unit tests are not run from within a debugger, but rather directly with pytest. They are located in the [`./tests/unit-tests/`](https://github.com/pwndbg/pwndbg/tree/dev/tests/unit-tests)
directory.

Here are the options supported by `./tests.sh` which you can get by running `./tests.sh -h`.
```
usage: tests.py [-h] [-t {gdb,cross-arch}] [-p] [-c] [-v] [-s] [--nix] [--collect-only] [test_name_filter]

Run tests.

positional arguments:
  test_name_filter      run only tests that match the regex

options:
  -h, --help            show this help message and exit
  -t, --type {gdb,cross-arch}
  -p, --pdb             enable pdb (Python debugger) post mortem debugger on failed tests
  -c, --cov             enable codecov
  -v, --verbose         display all test output instead of just failing test output
  -s, --serial          run tests one at a time instead of in parallel
  --nix                 run tests using built for nix environment
  --collect-only        only show the output of test collection, don't run any tests
```

## Writing tests

Each test is a Python function that runs inside of an isolated GDB session.
Using a [`pytest`](https://docs.pytest.org/en/latest/) fixture at the beginning of each test,
GDB will attach to a [`binary`](https://github.com/pwndbg/pwndbg/tree/dev/tests/gdb-tests/conftest.py)
or connect to a [`QEMU instance`](https://github.com/pwndbg/pwndbg/tree/dev/tests/qemu-tests/conftest.py).
Each test runs some commands and uses Python `assert` statements to verify correctness. We can access pwndbg
library code like `pwndbg.aglib.regs.rsp` as well as execute GDB commands with `gdb.execute()`.

We can take a look at [`tests/gdb-tests/tests/test_symbol.py`](https://github.com/pwndbg/pwndbg/tree/dev/tests/gdb-tests/tests/test_symbol.py)
for an example of a simple test. Looking at a simplified version of the top-level code, we have this:

```python
import gdb
import pwndbg
import tests

BINARY = tests.binaries.get("symbol_1600_and_752.out")
```

Since these tests run inside GDB, we can import the `gdb` Python library. We also import the `tests` module,
which makes it easy to get the path to the test binaries located in [`tests/gdb-tests/tests/binaries`](https://github.com/pwndbg/pwndbg/tree/dev/tests/gdb-tests/tests/binaries).
You should be able to reuse the binaries in this folder for most tests, but if not feel free to add a new one.

Here's a small snippet of the actual test:

```python
def test_hexdump(start_binary):
    start_binary(BINARY)
    pwndbg.config.hexdump_group_width.value = -1

    gdb.execute("set hexdump-byte-separator")
    stack_addr = pwndbg.aglib.regs.rsp - 0x100
```

`pytest` will run any function that starts with `test_` as a new test, so there is no need to register your new
test anywhere. The `start_binary` argument is a function that will run the binary you give it, and it will set
some common options before starting the binary. Using `start_binary` is recommended if you don't need any
additional customization to GDB settings before starting the binary, but if you do it's fine to not use it.

## QEMU Tests

Our `gdb-tests` run in x86. To debug other architectures, we use QEMU for emulation and attach to its debug
port. These tests are located in [`tests/qemu-tests/tests/user`](https://github.com/pwndbg/pwndbg/tree/dev/tests/qemu-tests/tests/user). Test creation is
identical to our x86 tests - create a Python function with a Pytest fixture name as the parameter (it matches
based on the name), and call the argument to start debugging a binary. The `qemu_assembly_run` fixture takes in
a Python string of assembly code, compiles it in the appropriate architecture, and runs it - no need to create
an external file or edit a Makefile.
