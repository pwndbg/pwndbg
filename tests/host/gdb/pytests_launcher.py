from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any
from typing import Callable
from typing import Coroutine

import coverage
import gdb
import pytest

PWNDBG_ROOT = os.environ["TEST_PWNDBG_ROOT"]

# Prepare the test host environment for the Debugger API tests.
host_home = f"{PWNDBG_ROOT}/tests/"
if host_home not in sys.path:
    sys.path.append(host_home)

import host


class _GDBController(host.Controller):
    async def launch(self, binary_path: Path) -> None:
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
        gdb.execute("starti " + " ".join(args))


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
