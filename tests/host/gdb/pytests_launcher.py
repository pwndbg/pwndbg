from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any
from typing import Callable
from typing import Coroutine
from typing import Dict
from typing import List

import coverage
import gdb
import pytest

from ... import host


class _GDBController(host.Controller):
    async def launch(
        self, binary_path: Path, args: List[str] = [], env: Dict[str, str] = {}
    ) -> None:
        """
        Launch the given binary.

        GDB hides the asynchronous heavy lifting from us, so this call is
        synchronous.
        """
        os.environ["PWNDBG_IN_TEST"] = "1"
        gdb.execute(f"file {binary_path}")
        gdb.execute("set exception-verbose on")
        gdb.execute("set width 80")
        gdb.execute("set context-reserve-lines never")
        os.environ["COLUMNS"] = "80"
        for k, v in env.items():
            gdb.execute(f"set environment {k}={v}")
        gdb.execute("starti " + " ".join(args))

    async def cont(self) -> None:
        gdb.execute("continue")

    async def execute(self, command: str) -> None:
        from pwndbg.dbg import Error

        try:
            gdb.execute(command)
        except gdb.error as e:
            raise Error(e)

    async def execute_and_capture(self, command: str) -> str:
        return gdb.execute(command, to_string=True)

    async def step_instruction(self) -> None:
        gdb.execute("stepi")

    async def finish(self) -> None:
        gdb.execute("finish")

    async def select_thread(self, tid: int) -> None:
        gdb.execute(f"thread {tid}")


def _start(outer: Callable[[host.Controller], Coroutine[Any, Any, None]]) -> None:
    # The GDB controller is entirely synchronous, so keep advancing the
    # corountine unconditionally until it ends..
    coroutine = outer(_GDBController())
    try:
        coroutine.send(None)
    except StopIteration:
        pass


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
