from __future__ import annotations

import gdb

import pwndbg.gdblib.tui.context
import pwndbg.gdblib.tui.control


def setup() -> None:
    tui_layouts = [
        (
            "tui new-layout pwndbg "
            "{-horizontal "
            " { "
            "  { -horizontal "
            "   { pwndbg_disasm 1 } 2 "
            "   { "
            "     { -horizontal pwndbg_legend 8 pwndbg_control 2 } 1 pwndbg_regs 6 pwndbg_stack 6 "
            "   } 3 "
            "  } 7 cmd 3 "
            " } 3 { pwndbg_backtrace 2 pwndbg_threads 1 pwndbg_expressions 2 } 1 "
            "} 1 status 1"
        ),
        (
            "tui new-layout pwndbg_code "
            "{-horizontal "
            " { "
            "  { -horizontal "
            "   { pwndbg_code 1 pwndbg_disasm 1 } 2 "
            "   { "
            "     { -horizontal pwndbg_legend 8 pwndbg_control 2 } 1 pwndbg_regs 6 pwndbg_stack 6 "
            "   } 3 "
            "  } 7 cmd 3 "
            " } 3 { pwndbg_backtrace 2 pwndbg_threads 1 pwndbg_expressions 2 } 1 "
            "} 1 status 1"
        ),
    ]
    for layout in tui_layouts:
        try:
            gdb.execute(layout)
        except gdb.error:
            pass
