# Writing tests

We have four types of tests: `gdb-tests`,`qemu-tests`, `unit-tests`, and Linux kernel tests, which are all located in subdirectories of [`tests`](https://github.com/pwndbg/pwndbg/tree/dev/tests).

`gdb-tests` refers to our x86 tests, which are located [`tests/gdb-tests`](tests/gdb-tests/).

To run these tests, run [`./tests.sh`](./tests.sh).  You can also drop into the PDB debugger when a test fails with `./tests.sh --pdb`.

To invoke cross-architecture tests, use `./qemu-tests.sh`, and to run unit tests, use `./unit-tests.sh`

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
