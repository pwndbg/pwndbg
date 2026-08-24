from __future__ import annotations

import os
import sys
import traceback

import gdb

from pwndbginit import gdbpatches  # noqa: F401
from pwndbginit.common import post_debugger_init
from pwndbginit.common import pre_debugger_init
from pwndbginit.common import setup_load_profiler
from pwndbginit.common import verify_venv


def check_doubleload() -> None:
    if "pwndbg" in sys.modules:
        print(
            "Detected double-loading of Pwndbg (likely from both .gdbinit and the Pwndbg portable build)."
        )
        print(
            "To fix this, please remove the line 'source your-path/gdbinit.py' from your .gdbinit file."
        )
        sys.exit(1)


def main() -> None:
    profiler, load_profile_start_time = setup_load_profiler()

    check_doubleload()
    verify_venv()

    # Force UTF-8 encoding (to_string=True to skip output appearing to the user)
    try:
        gdb.execute("set target-wide-charset UTF-8", to_string=True)
        gdb.execute("set charset UTF-8", to_string=True)
    except gdb.error as e:
        print(f"Warning: Cannot set gdb charset: '{e}'")

    import pwndbg  # noqa: F811

    log_handler = pre_debugger_init()

    import pwndbg.dbg_mod.gdb

    pwndbg.dbg = pwndbg.dbg_mod.gdb.GDB()
    pwndbg.dbg.setup()

    post_debugger_init(profiler, load_profile_start_time, log_handler)

    # We need reimport it here so that it's available at the global scope
    # when some starts a Python interpreter in GDB
    gdb.execute("py import pwndbg")


def main_try():
    # We wrap everything in try/except so that we can exit GDB with an error code
    # This is used by tests to check if gdbinit.py failed
    try:
        main()
    except Exception:
        print(traceback.format_exc(), file=sys.stderr, flush=True)
        os._exit(1)
