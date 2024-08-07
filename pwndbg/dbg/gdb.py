from __future__ import annotations

import contextlib
import signal
from typing import Any
from typing import List
from typing import Tuple
from typing import TypeVar

import gdb
from typing_extensions import Callable
from typing_extensions import Set
from typing_extensions import override

import pwndbg
import pwndbg.gdblib
import pwndbg.gdblib.events
from pwndbg.gdblib import gdb_version
from pwndbg.gdblib import load_gdblib

T = TypeVar("T")


# We pass the responsibility of event handling to gdblib.
GDBLIB_EVENT_MAPPING = {
    pwndbg.dbg_mod.EventType.EXIT: pwndbg.gdblib.events.exit,
    pwndbg.dbg_mod.EventType.CONTINUE: pwndbg.gdblib.events.cont,
    pwndbg.dbg_mod.EventType.START: pwndbg.gdblib.events.start,
    pwndbg.dbg_mod.EventType.STOP: pwndbg.gdblib.events.stop,
    pwndbg.dbg_mod.EventType.NEW_MODULE: pwndbg.gdblib.events.new_objfile,
    pwndbg.dbg_mod.EventType.MEMORY_CHANGED: pwndbg.gdblib.events.mem_changed,
    pwndbg.dbg_mod.EventType.REGISTER_CHANGED: pwndbg.gdblib.events.reg_changed,
}


class GDBRegisters(pwndbg.dbg_mod.Registers):
    def __init__(self, frame: GDBFrame):
        self.frame = frame

    @override
    def by_name(self, name: str) -> pwndbg.dbg_mod.Value | None:
        try:
            return GDBValue(self.frame.inner.read_register(name))
        except gdb.error:
            # GDB throws an exception if the name is unknown, we just return
            # None when that is the case.
            pass
        return None


def parse_and_eval(expression: str, global_context: bool) -> gdb.Value:
    """
    Same as `gdb.parse_and_eval`, but only uses `global_context` if it is
    supported by the current version of GDB.

    `global_context` was introduced in GDB 14.
    """
    try:
        return gdb.parse_and_eval(expression, global_context)
    except TypeError:
        return gdb.parse_and_eval(expression)


@contextlib.contextmanager
def selection(target: T, get_current: Callable[[], T], select: Callable[[T], None]):
    """
    GDB has a lot of global state. Many of our queries require that we select a
    given object globally before we make them. When doing that, we must always
    be careful to return selection to its previous state before exiting. This
    class automatically manages the selection of a single object type.

    Upon entrace to the `with` block, the element given by `target` will be
    compared to the object returned by calling `get_current`. If they
    compare different, the value previously returned by `get_current` is
    saved, and the element given by `target` will be selected by passing it
    as an argument to `select`, and, after execution leaves the `with`
    block, the previously saved element will be selected in the same fashion
    as the first element.

    If the elements don't compare different, this is a no-op.
    """

    current = get_current()
    restore = False
    if current != target:
        select(target)
        restore = True

    try:
        yield
    finally:
        if restore:
            select(current)


class GDBFrame(pwndbg.dbg_mod.Frame):
    def __init__(self, inner: gdb.Frame):
        self.inner = inner

    @override
    def evaluate_expression(self, expression: str) -> pwndbg.dbg_mod.Value:
        with selection(self.inner, lambda: gdb.selected_frame(), lambda f: f.select()):
            try:
                value = parse_and_eval(expression, global_context=False)
            except gdb.error as e:
                raise pwndbg.dbg_mod.Error(e)

        return GDBValue(value)

    @override
    def regs(self) -> pwndbg.dbg_mod.Registers:
        return GDBRegisters(self)


class GDBThread(pwndbg.dbg_mod.Thread):
    def __init__(self, inner: gdb.InferiorThread):
        self.inner = inner

    @override
    def bottom_frame(self) -> pwndbg.dbg_mod.Frame:
        with selection(self.inner, lambda: gdb.selected_thread(), lambda t: t.switch()):
            value = gdb.newest_frame()
        return GDBFrame(value)


class GDBProcess(pwndbg.dbg_mod.Process):
    def __init__(self, inner: gdb.Inferior):
        self.inner = inner

    @override
    def evaluate_expression(self, expression: str) -> pwndbg.dbg_mod.Value:
        try:
            return GDBValue(parse_and_eval(expression, global_context=True))
        except gdb.error as e:
            raise pwndbg.dbg_mod.Error(e)


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


class GDBType(pwndbg.dbg_mod.Type):
    CODE_MAPPING = {
        gdb.TYPE_CODE_INT: pwndbg.dbg_mod.TypeCode.INT,
        gdb.TYPE_CODE_UNION: pwndbg.dbg_mod.TypeCode.UNION,
        gdb.TYPE_CODE_STRUCT: pwndbg.dbg_mod.TypeCode.STRUCT,
        gdb.TYPE_CODE_ENUM: pwndbg.dbg_mod.TypeCode.ENUM,
        gdb.TYPE_CODE_TYPEDEF: pwndbg.dbg_mod.TypeCode.TYPEDEF,
        gdb.TYPE_CODE_PTR: pwndbg.dbg_mod.TypeCode.POINTER,
        gdb.TYPE_CODE_ARRAY: pwndbg.dbg_mod.TypeCode.ARRAY,
    }

    def __init__(self, inner: gdb.Type):
        self.inner = inner

    @property
    @override
    def alignof(self) -> int:
        return self.inner.alignof

    @property
    @override
    def code(self) -> pwndbg.dbg_mod.TypeCode:
        assert self.inner.code in GDBType.CODE_MAPPING, "missing mapping for type code"
        return GDBType.CODE_MAPPING[self.inner.code]

    @override
    def fields(self) -> List[pwndbg.dbg_mod.TypeField] | None:
        return [
            pwndbg.dbg_mod.TypeField(
                field.bitpos,
                field.name,
                GDBType(field.type),
                field.parent_type,
                field.enumval,
                field.artificial,
                field.is_base_class,
                field.bitsize,
            )
            for field in self.inner.fields()
        ]

    @override
    def array(self, count: int) -> pwndbg.dbg_mod.Type:
        return GDBType(self.inner.array(count))

    @override
    def pointer(self) -> pwndbg.dbg_mod.Type:
        return GDBType(self.inner.pointer())

    @override
    def strip_typedefs(self) -> pwndbg.dbg_mod.Type:
        return GDBType(self.inner.strip_typedefs())

    @override
    def target(self) -> pwndbg.dbg_mod.Type:
        return GDBType(self.inner.target())


class GDBValue(pwndbg.dbg_mod.Value):
    def __init__(self, inner: gdb.Value):
        self.inner = inner

    @property
    @override
    def address(self) -> pwndbg.dbg_mod.Value | None:
        return GDBValue(self.inner.address)

    @property
    @override
    def is_optimized_out(self) -> bool:
        return self.inner.is_optimized_out

    @property
    @override
    def type(self) -> pwndbg.dbg_mod.Type:
        return GDBType(self.inner.type)

    @override
    def dereference(self) -> pwndbg.dbg_mod.Value:
        return GDBValue(self.inner.dereference())

    @override
    def string(self) -> str:
        return self.inner.string()

    @override
    def fetch_lazy(self) -> None:
        self.inner.fetch_lazy()

    @override
    def __int__(self) -> int:
        try:
            return int(self.inner)
        except gdb.error as e:
            raise pwndbg.dbg_mod.Error(e)

    @override
    def cast(self, type: pwndbg.dbg_mod.Type | Any) -> pwndbg.dbg_mod.Value:
        # We let the consumers of this function just pass it a `gdb.Type`.
        # This keeps us from breaking functionality under GDB until we have
        # better support for type lookup under LLDB and start porting the
        # commands that need this to the new API.
        #
        # FIXME: Remove sloppy `gdb.Type` exception in `GDBValue.cast()`
        if isinstance(type, gdb.Type):
            return GDBValue(self.inner.cast(type))

        assert isinstance(type, GDBType)
        t: GDBType = type

        return GDBValue(self.inner.cast(t.inner))


class GDB(pwndbg.dbg_mod.Debugger):
    @override
    def setup(self):
        from pwndbg.commands import load_commands

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
    def selected_thread(self) -> pwndbg.dbg_mod.Thread | None:
        thread = gdb.selected_thread()
        if thread:
            return GDBThread(thread)
        return None

    @override
    def selected_frame(self) -> pwndbg.dbg_mod.Frame | None:
        try:
            frame = gdb.selected_frame()
            if frame:
                return GDBFrame(frame)
        except gdb.error:
            pass
        return None

    def commands(self):
        current_pagination = gdb.execute("show pagination", to_string=True)
        current_pagination = current_pagination.split()[-1].rstrip(
            "."
        )  # Take last word and skip period

        gdb.execute("set pagination off")
        command_list = gdb.execute("help all", to_string=True).strip().split("\n")
        existing_commands: Set[str] = set()
        for line in command_list:
            line = line.strip()
            # Skip non-command entries
            if (
                not line
                or line.startswith("Command class:")
                or line.startswith("Unclassified commands")
            ):
                continue
            command = line.split()[0]
            existing_commands.add(command)
        gdb.execute(f"set pagination {current_pagination}")  # Restore original setting
        return existing_commands

    @override
    def selected_inferior(self) -> pwndbg.dbg_mod.Process | None:
        return GDBProcess(gdb.selected_inferior())

    @override
    def is_gdblib_available(self):
        return True

    @override
    def has_event_type(self, ty: pwndbg.dbg_mod.EventType) -> bool:
        # Currently GDB supports all event types.
        return True

    @override
    def event_handler(
        self, ty: pwndbg.dbg_mod.EventType
    ) -> Callable[[Callable[..., T]], Callable[..., T]]:
        # Just call into the gdblib handler.
        return GDBLIB_EVENT_MAPPING[ty]

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
