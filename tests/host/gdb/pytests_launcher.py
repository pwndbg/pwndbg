from __future__ import annotations

import contextlib
import os
import sys
from collections.abc import Callable
from collections.abc import Coroutine
from pathlib import Path
from typing import Any

import coverage
import gdb
import pytest

from ... import host


class _GDBController(host.Controller):
    def _gdb_execute(self, command: str) -> None:
        """Execute a GDB command and print the command to output."""
        print(f"pwndbg> {command}")
        gdb.execute(command)

    def _show_context(self) -> None:
        """
        Display context after stops during tests.

        We run the context command directly instead of using prompt_hook()
        because prompt_hook() also fires events via after_reload(), which
        can cause event handlers to trigger multiple times.
        """
        self._gdb_execute("context")

    async def launch(self, binary: Path, args: list[str] = [], env: dict[str, str] = {}) -> None:
        """
        Launch the given binary.

        GDB hides the asynchronous heavy lifting from us, so this call is
        synchronous.
        """
        if not os.path.exists(binary):
            pytest.skip(f"{os.path.basename(binary)} does not exist. Platform not supported.")

        os.environ["PWNDBG_IN_TEST"] = "1"
        self._gdb_execute(f"file {binary}")
        self._gdb_execute("set exception-verbose on")
        self._gdb_execute("set width 80")
        self._gdb_execute("set context-reserve-lines never")
        os.environ["COLUMNS"] = "80"
        for k, v in env.items():
            self._gdb_execute(f"set environment {k}={v}")
        # Clear breakpoints from any prior launch. The debugger abstraction
        # layer sets breakpoints by resolved address (not by symbol name), so
        # GDB won't re-resolve them on relaunch. With ASLR, stale address
        # breakpoints point to invalid memory and cause "Cannot access memory"
        # errors on starti.
        self._gdb_execute("delete breakpoints")
        self._gdb_execute("starti " + " ".join(args))
        self._show_context()

    async def cont(self) -> None:
        self._gdb_execute("continue")
        self._show_context()

    async def execute(self, command: str) -> None:
        from pwndbg.dbg_mod import Error

        try:
            self._gdb_execute(command)
        except gdb.error as e:
            raise Error(e)

    async def execute_and_capture(self, command: str) -> str:
        print(f"pwndbg> {command}")
        result = gdb.execute(command, to_string=True)
        print(result)
        return result

    async def step_instruction(self) -> None:
        self._gdb_execute("stepi")
        self._show_context()

    async def finish(self) -> None:
        self._gdb_execute("finish")
        self._show_context()

    async def select_thread(self, tid: int) -> None:
        self._gdb_execute(f"thread {tid}")

    async def disable_debuginfod(self) -> None:
        self._gdb_execute("set debug-file-directory")
        self._gdb_execute("set debuginfod enabled off")

    async def generate_core_file(self, path: Path) -> None:
        self._gdb_execute(f"generate-core-file {path}")
        self._gdb_execute(f"core-file {path}")


def _start(outer: Callable[[host.Controller], Coroutine[Any, Any, None]]) -> None:
    # The GDB controller is entirely synchronous, so keep advancing the
    # corountine unconditionally until it ends..
    coroutine = outer(_GDBController())
    with contextlib.suppress(StopIteration):
        coroutine.send(None)


host.start = _start

# Start the test, proper.
use_pdb = os.environ.get("USE_PDB") == "1"

sys._pwndbg_unittest_run = True  # type: ignore[attr-defined]

test = os.environ["PWNDBG_LAUNCH_TEST"]

args = [test, "-vvv", "-s", "--showlocals", "--color=yes"]

if use_pdb:
    args.append("--pdb")

print(f"Launching pytest with args: {args}")

return_code = pytest.main(args)

if return_code != 0:
    print("-" * 80)
    print("If you want to debug tests locally, run ./tests.sh with the --pdb flag")
    print("-" * 80)

# We must call these functions manually to flush the code coverage data to disk since the sys.exit() call
# might've been replaced by os._exit() in gdbinit.py.
# https://github.com/nedbat/coveragepy/issues/310
if (cov := coverage.Coverage.current()) is not None:
    cov.stop()
    cov.save()

# `sys.exit` triggers a GDB detach, while `os._exit` does not.
# This allows the debugging session to remain at the same PC location,
# which is useful for attaching to qemu-system multiple times.
sys.stdout.flush()
sys.stderr.flush()
os._exit(return_code)
