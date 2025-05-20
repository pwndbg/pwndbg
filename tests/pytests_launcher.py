from __future__ import annotations

import os
import sys

import coverage
import pytest

use_pdb = os.environ.get("USE_PDB") == "1"

sys._pwndbg_unittest_run = True

CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))

test = os.environ["PWNDBG_LAUNCH_TEST"]

test = os.path.join(CURRENT_DIR, test)

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
