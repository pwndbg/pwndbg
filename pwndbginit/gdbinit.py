from __future__ import annotations

import logging
import os
import sys
import traceback
from typing import TextIO

import gdb

from pwndbginit import gdbpatches  # noqa: F401
from pwndbginit.common import post_debugger_init
from pwndbginit.common import pre_debugger_init
from pwndbginit.common import setup_load_profiler
from pwndbginit.common import verify_venv


def init_logger() -> logging.StreamHandler[TextIO]:
    log_level_env = os.environ.get("PWNDBG_LOGLEVEL", "WARNING")
    log_level = getattr(logging, log_level_env.upper())

    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)

    # Add a custom StreamHandler we will use to customize log message formatting. We
    # configure the handler later, after pwndbg has been imported.
    handler = logging.StreamHandler()
    root_logger.addHandler(handler)

    return handler


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
    handler = init_logger()
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

    # Mark that pwndbg was loaded from `pwndbg` binary (for double-load detection)
    pwndbg._is_loaded_from_pwndbg = True

    # FIXME: move above line here?
    pre_debugger_init()

    import pwndbg.dbg_mod.gdb

    pwndbg.dbg = pwndbg.dbg_mod.gdb.GDB()
    pwndbg.dbg.setup()

    # ColorFormatter relies on pwndbg being loaded, so we can't set it up until now
    import pwndbg.log

    handler.setFormatter(pwndbg.log.ColorFormatter())

    # FIXME: put log handler in here?
    # FIXME: put this below `py import pwndbg`?
    post_debugger_init(profiler, load_profile_start_time)

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
