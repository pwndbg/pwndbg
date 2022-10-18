import os
import sys

import pytest

use_pdb = os.environ.get("USE_PDB") == "1"

sys._pwndbg_unittest_run = True

CURRENT_DIR = os.path.dirname(os.path.realpath(__file__))

test = os.environ["PWNDBG_LAUNCH_TEST"]

test = os.path.join(CURRENT_DIR, test)

args = [test, "-vvv", "-s", "--showlocals", "--color=yes"]

if use_pdb:
    args.append("--pdb")

print("Launching pytest with args: %s" % args)

return_code = pytest.main(args)

if return_code != 0:
    print("-" * 80)
    print(
        "If you want to debug tests locally, modify {} and add --pdb to its args".format(__file__)
    )
    print("-" * 80)

sys.exit(return_code)
