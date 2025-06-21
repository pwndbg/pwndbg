from __future__ import annotations

import cProfile
import logging
import os
import sys
import time
import traceback

import gdb

from pwndbginit import gdbpatches  # noqa: F401
from pwndbginit.common import verify_venv


def init_logger():
    log_level_env = os.environ.get("PWNDBG_LOGLEVEL", "WARNING")
    log_level = getattr(logging, log_level_env.upper())

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Add a custom StreamHandler we will use to customize log message formatting. We
    # configure the handler later, after pwndbg has been imported.
    handler = logging.StreamHandler()
    root_logger.addHandler(handler)

    return handler


def check_doubleload():
    if "pwndbg" in sys.modules:
        print(
            "Detected double-loading of Pwndbg (likely from both .gdbinit and the Pwndbg portable build)."
        )
        print(
            "To fix this, please remove the line 'source your-path/gdbinit.py' from your .gdbinit file."
        )
        sys.exit(1)


def main() -> None:
    handler = init_logger()
    profiler = cProfile.Profile()

    start_time = None
    if os.environ.get("PWNDBG_PROFILE") == "1":
        start_time = time.time()
        profiler.enable()

    check_doubleload()
    verify_venv()

    # Force UTF-8 encoding (to_string=True to skip output appearing to the user)
    try:
        gdb.execute("set target-wide-charset UTF-8", to_string=True)
        gdb.execute("set charset UTF-8", to_string=True)
    except gdb.error as e:
        print(f"Warning: Cannot set gdb charset: '{e}'")

    import pwndbg  # noqa: F811
    import pwndbg.dbg.gdb

    pwndbg.dbg = pwndbg.dbg_mod.gdb.GDB()
    pwndbg.dbg.setup()

    import pwndbg.log
    import pwndbg.profiling

    # ColorFormatter relies on pwndbg being loaded, so we can't set it up until now
    handler.setFormatter(pwndbg.log.ColorFormatter())

    pwndbg.profiling.init(profiler, start_time)
    if os.environ.get("PWNDBG_PROFILE") == "1":
        pwndbg.profiling.profiler.stop("pwndbg-load.pstats")
        pwndbg.profiling.profiler.start()

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
