from __future__ import annotations

import cProfile
import os
import sys
import time
from typing import Tuple

import lldb

from pwndbginit.common import verify_venv


def main(debugger: lldb.SBDebugger, lldb_version: Tuple[int, ...], debug: bool = False) -> None:
    if "pwndbg" in sys.modules:
        print("Detected double-loading of Pwndbg.")
        print("This should not happen. Please report this issue if you're not sure how to fix it.")
        sys.exit(1)

    verify_venv()
    profiler = cProfile.Profile()

    start_time = None
    if os.environ.get("PWNDBG_PROFILE") == "1":
        start_time = time.time()
        profiler.enable()

    import pwndbg  # noqa: F811
    import pwndbg.dbg.lldb

    pwndbg.dbg_mod.lldb.LLDB_VERSION = lldb_version

    pwndbg.dbg = pwndbg.dbg_mod.lldb.LLDB()
    pwndbg.dbg.setup(debugger, "pwndbglldbhandler", debug=debug)

    import pwndbg.profiling

    pwndbg.profiling.init(profiler, start_time)
    if os.environ.get("PWNDBG_PROFILE") == "1":
        pwndbg.profiling.profiler.stop("pwndbg-load.pstats")
        pwndbg.profiling.profiler.start()
