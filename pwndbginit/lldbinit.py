from __future__ import annotations

import sys

import lldb

from pwndbginit.common import init_logger
from pwndbginit.common import post_debugger_init
from pwndbginit.common import pre_debugger_init
from pwndbginit.common import setup_load_profiler
from pwndbginit.common import verify_venv


def check_doubleload() -> None:
    if "pwndbg" in sys.modules:
        print("Detected double-loading of Pwndbg.")
        print("This should not happen. Please report this issue if you're not sure how to fix it.")
        sys.exit(1)


def main(debugger: lldb.SBDebugger, lldb_version: tuple[int, ...], debug: bool = False) -> None:
    profiler, load_profile_start_time = setup_load_profiler()
    log_handler = init_logger()

    check_doubleload()
    verify_venv()

    import pwndbg  # noqa: F811

    pre_debugger_init()

    import pwndbg.dbg_mod.lldb

    pwndbg.dbg_mod.lldb.LLDB_VERSION = lldb_version
    pwndbg.dbg = pwndbg.dbg_mod.lldb.LLDB()
    pwndbg.dbg.setup(debugger, "pwndbglldbhandler", debug=debug)

    post_debugger_init(profiler, load_profile_start_time, log_handler)
