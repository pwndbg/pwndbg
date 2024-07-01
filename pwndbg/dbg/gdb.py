from __future__ import annotations

import signal
from typing import Any
from typing import List
from typing import Tuple

import gdb
from typing_extensions import Callable
from typing_extensions import override

import pwndbg
import pwndbg.commands
import pwndbg.gdblib
from pwndbg.commands import load_commands
from pwndbg.gdblib import gdb_version
from pwndbg.gdblib import load_gdblib


class GDBCommand(gdb.Command):
    def __init__(
        self,
        debugger: GDB,
        name: str,
        handler: Callable[[pwndbg.dbg_mod.Debugger, str, bool], None],
    ):
        self.debugger = debugger
        self.handler = handler
        super().__init__(name, gdb.COMMAND_USER, gdb.COMPLETE_EXPRESSION)

    def invoke(self, args: str, from_tty: bool) -> None:
        self.handler(self.debugger, args, from_tty)


class GDBCommandHandle(pwndbg.dbg_mod.CommandHandle):
    def __init__(self, command: gdb.Command):
        self.command = command

    def remove(self) -> None:
        # GDB doesn't support command removal.
        pass


class GDB(pwndbg.dbg_mod.Debugger):
    @override
    def setup(self):
        load_gdblib()
        load_commands()

        # Importing `pwndbg.gdblib.prompt` ends up importing code that has the
        # side effect of setting a command up. Because command setup requires
        # `pwndbg.dbg` to already be set, and this module is used as part of the
        # process of setting it, we have to wait, and do the import as part of
        # this method.
        from pwndbg.gdblib import prompt

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

        prompt.show_hint()

    @override
    def add_command(
        self, name: str, handler: Callable[[pwndbg.dbg_mod.Debugger, str, bool], None]
    ) -> pwndbg.dbg_mod.CommandHandle:
        command = GDBCommand(self, name, handler)
        return GDBCommandHandle(command)

    @override
    def history(self, last: int = 10) -> List[Tuple[int, str]]:
        # GDB displays commands in groups of 10. We might want more than that,
        # so we fetch multiple blocks of 10 and assemble them into the final
        # history in a second step.
        parsed_blocks = []
        parsed_lines_count = 0
        parsed_lines_min = None
        parsed_lines_max = None
        parsed_lines_base = None

        while parsed_lines_count < last:
            # Fetch and parse the block we're currently interested in.
            base = f" {parsed_lines_base}" if parsed_lines_base else ""

            lines = gdb.execute(f"show commands{base}", from_tty=False, to_string=True)
            lines = lines.splitlines()

            parsed_lines = []
            for line in lines:
                number_str, command = line.split(maxsplit=1)
                try:
                    number = int(number_str)
                except ValueError:
                    # In rare cases GDB will output a warning after executing `show commands`
                    # (i.e. "warning: (Internal error: pc 0x0 in read in CU, but not in
                    # symtab.)").
                    return []

                parsed_lines.append((number, command))

            # We have nothing more to parse if GDB gives us nothing here.
            if len(parsed_lines) == 0:
                break

            # Set the maximum command index we know about. This is simply the
            # last element of the first block.
            if not parsed_lines_max:
                parsed_lines_max = parsed_lines[-1][0]

            # Keep track of the minimum command index we've seen.
            #
            # This is usually the first element in the most recent block, but
            # GDB isn't very clear about whether running commands with
            # `gdb.execute` affects the command history, and what the exact size
            # of the command history is. This means that, at the very end, the
            # first index in the last block might be one greater than the last
            # index in the second-to-last block.
            #
            # Additionally, the value of the first element being greater than
            # the minimum also means that we reached the end of the command
            # history on the last block, can break out of the loop early, and
            # don't even need to bother with this block.
            if parsed_lines_min:
                if parsed_lines[0][0] < parsed_lines_min:
                    parsed_lines_min = parsed_lines[0][0]
                else:
                    break
            else:
                parsed_lines_min = parsed_lines[0][0]

            parsed_blocks.append(parsed_lines)
            parsed_lines_count += len(parsed_lines)

            # If we've just pulled the block with command index 0, we know we
            # can't possibly go back any farther.
            if parsed_lines_base == 0:
                break

            # The way GDB displays the command history is _weird_. The argument
            # we pass to `show commands <arg>` is the index of the 6th element
            # in the block, meaning we'll get a block whose values range from
            # at most <arg> - 5 to at most <arg> + 4, inclusive.
            #
            # Given that we want the first element in this block to the just one
            # past the maximum range of the block returned by the next arguemnt,
            # and that we know the last element in a block is at most <arg> + 4,
            # we can subtract five from its index to land in the right spot.
            parsed_lines_base = max(0, parsed_lines[0][0] - 5)

        # We've got nothing.
        if len(parsed_blocks) == 0:
            return []

        # Sort the elements in the block into the final history array.
        remaining = parsed_lines_max - parsed_lines_min + 1
        plines: List[Tuple[int, str]] = [None] * remaining
        while remaining > 0 and len(parsed_blocks) > 0:
            block = parsed_blocks.pop()
            for pline in block:
                index = pline[0] - parsed_lines_min
                if not plines[index]:
                    plines[pline[0] - parsed_lines_min] = pline
                    remaining -= 1

        # If this fails, either some of our assumptions were wrong, or GDB is
        # doing something funky with the output, either way, not good.
        assert remaining == 0, "There are gaps in the command history"

        return plines[-last:]

    @override
    def lex_args(self, command_line: str) -> List[str]:
        return gdb.string_to_argv(command_line)

    @override
    def addrsz(self, address: Any) -> str:
        address = int(address) & pwndbg.gdblib.arch.ptrmask
        return f"%#{2 * pwndbg.gdblib.arch.ptrsize}x" % address

    @override
    def get_cmd_window_size(self) -> Tuple[int, int]:
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

    @override
    def set_python_diagnostics(self, enabled: bool) -> None:
        if enabled:
            command = "set python print-stack full"
        else:
            command = "set python print-stack message"

        gdb.execute(command, from_tty=True, to_string=True)
