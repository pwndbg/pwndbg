from __future__ import annotations

import signal

import gdb

import pwndbg
import pwndbg.commands
import pwndbg.gdblib
from pwndbg.commands import load_commands
from pwndbg.gdblib import gdb_version
from pwndbg.gdblib import load_gdblib
from pwndbg.gdblib import prompt


class GDB(pwndbg.dbg_mod.Debugger):
    def setup(self):
        load_gdblib()
        load_commands()

        prompt.set_prompt()

        pre_commands = f"""
        set confirm off
        set verbose off
        set pagination off
        set height 0
        set history save on
        set follow-fork-mode child
        set backtrace past-main on
        set step-mode on
        set print pretty on
        set width {pwndbg.ui.get_window_size()[1]}
        handle SIGALRM nostop print nopass
        handle SIGBUS  stop   print nopass
        handle SIGPIPE nostop print nopass
        handle SIGSEGV stop   print nopass
        """.strip()

        # See https://github.com/pwndbg/pwndbg/issues/808
        if gdb_version[0] <= 9:
            pre_commands += "\nset remote search-memory-packet off"

        for line in pre_commands.strip().splitlines():
            gdb.execute(line)

        # This may throw an exception, see pwndbg/pwndbg#27
        try:
            gdb.execute("set disassembly-flavor intel")
        except gdb.error:
            pass

        # handle resize event to align width and completion
        signal.signal(
            signal.SIGWINCH,
            lambda signum, frame: gdb.execute("set width %i" % pwndbg.ui.get_window_size()[1]),
        )

        # Reading Comment file
        from pwndbg.commands import comments

        comments.init()

        from pwndbg.gdblib import config_mod

        config_mod.init_params()

    def addrsz(self, address):
        address = int(address) & pwndbg.gdblib.arch.ptrmask
        return f"%#{2 * pwndbg.gdblib.arch.ptrsize}x" % address

    def get_cmd_window_size(self):
        """Get the size of the command window in TUI mode which could be different than the terminal window width \
        with horizontal split "tui new-layout hsrc { -horizontal src 1 cmd 1 } 1".

        Possible output of "info win" in TUI mode:
        (gdb) info win
        Name       Lines Columns Focus
        src           77     104 (has focus)
        cmd           77     105

        Output of "info win" in non-TUI mode:
        (gdb) info win
        The TUI is not active."""
        try:
            info_out = gdb.execute("info win", to_string=True).split()
        except gdb.error:
            # Return None if the command is not compiled into GDB
            # (gdb.error: Undefined info command: "win".  Try "help info")
            return None, None
        if "cmd" not in info_out:
            # if TUI is not enabled, info win will output "The TUI is not active."
            return None, None
        # parse cmd window size from the output of "info win"
        cmd_win_index = info_out.index("cmd")
        if len(info_out) <= cmd_win_index + 2:
            return None, None
        elif (
            not info_out[cmd_win_index + 1].isdigit() and not info_out[cmd_win_index + 2].isdigit()
        ):
            return None, None
        else:
            return int(info_out[cmd_win_index + 1]), int(info_out[cmd_win_index + 2])

    def set_python_diagnostics(self, enabled):
        if enabled:
            command = "set python print-stack full"
        else:
            command = "set python print-stack message"

        gdb.execute(command, from_tty=True, to_string=True)
