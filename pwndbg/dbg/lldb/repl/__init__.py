"""
The Pwndbg REPL that is the interface to all debugging on LLDB.

Pwndbg has an event system that allows it to react to events in the process
being debugged, such as when new executable modules get added to the its address
space, when the value of memory and registers change, and pretty much all
possible changes to its execution state. We'd like to have the event system work
the same way under LLDB as it does under GDB.

Fortunately for us, the events types that are native to LLDB map really well to
the event types in GDB and Pwndbg. Very, very unfortunately for us, however,
that's basically where our luck ends.

LLDB, as of version 18, only provides two ways to capture events: registering
directly with the broadcaster, or registering globally. The former is not
available to us in the standard LLDB REPL, as we don't get access to the process
object until after it's been launched[1]. Likewise for the latter, as the
interactive debugger will register to receive the global process state change
events before everyone else, and LLDB doesn't allow for multiple listeners for
the same event bits in the same event class[2].

This leaves us with handling process management ourselves as the only option we
really have to implement event dispatch in Pwndbg. Easy, right? We can just
hijack the commands that deal with target and process creation, and leave
everything else untouched. Unfortunately for us, again, shadowing builtin
commands is simply not allowed[3][4].

So, really, all that's left for us is either implement our own REPL, or get rid
of the event system.

[1]: https://discourse.llvm.org/t/understanding-debugger-launch-events-sequence/39717/2
[2]: https://github.com/llvm/llvm-project/blob/3b5b5c1ec4a3095ab096dd780e84d7ab81f3d7ff/lldb/source/Utility/Broadcaster.cpp#L409
[3]: https://github.com/llvm/llvm-project/blob/3b5b5c1ec4a3095ab096dd780e84d7ab81f3d7ff/lldb/source/Commands/CommandObjectCommands.cpp#L439
[4]: https://github.com/llvm/llvm-project/blob/3b5b5c1ec4a3095ab096dd780e84d7ab81f3d7ff/lldb/source/Interpreter/CommandInterpreter.cpp#L1157
"""

from __future__ import annotations

import argparse
import asyncio
import os
import re
import shutil
import signal
import sys
import threading
from contextlib import contextmanager
from io import BytesIO
from io import TextIOBase
from io import TextIOWrapper
from typing import Any
from typing import Awaitable
from typing import BinaryIO
from typing import Callable
from typing import Coroutine
from typing import List
from typing import Tuple

import lldb
from typing_extensions import override

import pwndbg
import pwndbg.dbg.lldb
from pwndbg.color import message
from pwndbg.dbg import EventType
from pwndbg.dbg.lldb import LLDB
from pwndbg.dbg.lldb import LLDBProcess
from pwndbg.dbg.lldb import OneShotAwaitable
from pwndbg.dbg.lldb.pset import InvalidParse
from pwndbg.dbg.lldb.pset import pget
from pwndbg.dbg.lldb.pset import pset
from pwndbg.dbg.lldb.repl.io import IODriver
from pwndbg.dbg.lldb.repl.io import get_io_driver
from pwndbg.lib.tips import color_tip
from pwndbg.lib.tips import get_tip_of_the_day

HAS_FZF = shutil.which("fzf") is not None
if HAS_FZF:
    from pwndbg.dbg.lldb.repl.fuzzy import PROMPT
    from pwndbg.dbg.lldb.repl.fuzzy import get_prompt_session
    from pwndbg.dbg.lldb.repl.fuzzy import wrap_with_history
else:
    from pwndbg.dbg.lldb.repl.readline import PROMPT
    from pwndbg.dbg.lldb.repl.readline import enable_readline
    from pwndbg.dbg.lldb.repl.readline import wrap_with_history


def print_error(msg: str, *args):
    """
    Print an error message in the style of the LLDB CLI.
    """
    print(message.error("error:"), msg, *args)


def print_warn(msg: str, *args):
    """
    Print a warning message in the style of the LLDB CLI.
    """
    print(message.warn("warn:"), msg, *args)


def print_hint(msg: str, *args):
    """
    Print a hint message in the style of the LLDB CLI.
    """
    print(message.hint("hint:"), msg, *args)


def print_info(msg: str, *args):
    """
    Print an information message in the style of the LLDB CLI.
    """
    print(message.info("info:"), msg, *args)


from pwndbg.dbg.lldb.repl.proc import EventHandler
from pwndbg.dbg.lldb.repl.proc import LaunchResultConnected
from pwndbg.dbg.lldb.repl.proc import LaunchResultEarlyExit
from pwndbg.dbg.lldb.repl.proc import LaunchResultError
from pwndbg.dbg.lldb.repl.proc import LaunchResultSuccess
from pwndbg.dbg.lldb.repl.proc import ProcessDriver

show_tip = pwndbg.config.add_param(
    "show-tips", True, "whether to display the tip of the day on startup"
)

# We only allow certain commands to be executed in LLDB mode. This list contains
# tuples made up of the full name of the command and functions that check if a
# given command matches it.
LLDB_EXCLUSIVE = [
    ("script", lambda cmd: cmd.startswith("sc") and "script".startswith(cmd)),
    ("expression", lambda cmd: cmd.startswith("e") and "expression".startswith(cmd)),
]


def lex_args(args: str) -> List[str]:
    """
    Splits the arguments, respecting quotation marks.
    """
    args = args.strip()
    result = []
    while len(args) > 0:
        first = re.match("\\s*(\".*\"|'.*'|\\S+)", args)
        sl = first[1]

        # Handle single and double quotes, we could do some escaping for the
        # double quotes case, but we don't, yet.
        sl = sl.strip('"')
        sl = sl.strip("'")

        result.append(sl)
        args = args[first.end() :]

    return result


class EventRelay(EventHandler):
    """
    The event system that is sensible for the REPL process driver to use isn't
    an exact match with the one used by the rest of Pwndbg. They're close, but
    there's a bit of work we have to do to properly convey certain events.
    """

    def __init__(self, dbg: LLDB):
        self.dbg = dbg
        self.ignore_resumed = 0

    def _set_ignore_resumed(self, count: int):
        """
        Don't relay next given number of resumed events.
        """
        self.ignore_resumed += count

    @override
    def created(self):
        self.dbg._trigger_event(EventType.START)

    @override
    def suspended(self, event: lldb.SBEvent):
        # The event might have originated from a different source than the user
        # currently has selected. Move focus to the where the event happened.
        #
        # state-changed events have no thread associated with them, and so
        # SBThread::GetThreadFromEvent does not work. Interrogate each thread in
        # the process and look for the most interesting one.
        proc = lldb.SBProcess.GetProcessFromEvent(event)
        for thread in proc.threads:
            # Currently the one considered most interesting is simply the first
            # that has any reason at all to be stopped.
            if thread.stop_reason == lldb.eStopReasonNone:
                continue

            if proc.GetSelectedThread().idx != thread.idx:
                print(message.notice(f"[Switched to Thread {thread.id}]"))
                assert proc.SetSelectedThread(thread)
            break

        self.dbg._trigger_event(EventType.STOP)

    @override
    def resumed(self):
        if self.ignore_resumed > 0:
            self.ignore_resumed -= 1
            return

        self.dbg._trigger_event(EventType.CONTINUE)

    @override
    def exited(self):
        self.dbg._trigger_event(EventType.EXIT)

    @override
    def modules_loaded(self):
        self.dbg._trigger_event(EventType.NEW_MODULE)


def show_greeting() -> None:
    """
    Show the Pwndbg greeting, the same way the GDB version of Pwndbg would. This
    one is considerably simpler than the GDB version, however, as we control the
    lifetime of the program, we know exactly when the greeting needs to be shown,
    so we don't bother with any of the lifetime checks.
    """
    hint_lines = ("loaded %i pwndbg commands commands." % len(pwndbg.commands.commands),)

    for line in hint_lines:
        print(message.prompt("pwndbg: ") + message.system(line))

    if show_tip:
        colored_tip = color_tip(get_tip_of_the_day())
        print(
            message.prompt("------- tip of the day (some of these don't work in LLDB yet!)")
            + message.system(" (disable with %s)" % message.notice("set show-tips off"))
            + message.prompt(" -------")
        )
        print(colored_tip)


class YieldExecDirect:
    """
    Execute the given command directly, on behalf of the user.
    """

    def __init__(self, command: str, capture: bool, prompt_silent: bool):
        self._command = command
        self._capture = capture
        self._prompt_silent = prompt_silent


class YieldInteractive:
    """
    Prompt the user for the next command.
    """

    pass


class PwndbgController:
    """
    Class providing interfaces for a client to control the behavior of Pwndbg
    asynchronously.
    """

    def interactive(self) -> Awaitable[None]:
        """
        Runs a single interactive round, in which the user is prompted for a
        command from standard input and `readline`, and whatever command they
        type in is executed.
        """
        return OneShotAwaitable(YieldInteractive())

    def execute(self, command: str) -> Awaitable[None]:
        """
        Runs the given command, and displays its output to the user.

        # Interactivity
        Some commands - such as `lldb` and `ipi` - start interactive prompts
        when they are run, and issuing them through this command will not change
        that behavior.
        """
        return OneShotAwaitable(YieldExecDirect(command, False, False))

    def execute_and_capture(self, command: str) -> Awaitable[bytes]:
        """
        Runs the given command, and captures its output as a byte string.

        # Interactivity
        Same caveats apply as in `execute`.

        # Reliabily of Capture
        Some Pwndbg commands currently do not have their outputs captured, even
        when run through this command. It is expected that this will be improved
        in the future, but, as as general rule, clients should not rely on the
        output of the command being available.
        """
        return OneShotAwaitable(YieldExecDirect(command, True, False))


@wrap_with_history
def run(
    controller: Callable[..., Coroutine[Any, Any, None]],
    *args,
    debug: bool = False,
) -> None:
    """
    Runs the Pwndbg CLI through the given asynchronous controller.
    """

    assert isinstance(pwndbg.dbg, LLDB)
    dbg: LLDB = pwndbg.dbg

    if HAS_FZF:
        session = get_prompt_session(dbg)
    else:
        enable_readline(dbg)

    # We're gonna be dealing with process events ourselves, so we'll want to run
    # LLDB in asynchronous mode.
    dbg.debugger.SetAsync(True)

    # This is the driver we're going to be using to handle the process.
    relay = EventRelay(dbg)
    driver = ProcessDriver(debug=debug, event_handler=relay)

    # Set ourselves up to respond to SIGINT by interrupting the process if it is
    # running, and doing nothing otherwise.
    def handle_sigint(_sig, _frame):
        driver.cancel()
        if driver.has_process():
            driver.interrupt()
            print()

    signal.signal(signal.SIGINT, handle_sigint)

    show_greeting()
    last_command = ""

    coroutine = controller(PwndbgController(), *args)
    last_result: Any = None
    last_exc: Exception | None = None

    while True:
        # Execute the prompt hook.
        dbg._fire_prompt_hook()

        try:
            if last_exc is not None:
                action = coroutine.throw(last_exc)
            else:
                action = coroutine.send(last_result)
        except StopIteration:
            # Nothing else for us to do.
            break
        except asyncio.CancelledError:
            # We requested a cancellation that wasn't overwritten.
            break
        finally:
            last_exc = None
            last_result = None

        if isinstance(action, YieldInteractive):
            if debug:
                print("[-] REPL: Prompt next command from user interactively")

            try:
                if HAS_FZF:
                    try:
                        line = session.prompt(message=PROMPT)
                    except KeyboardInterrupt:
                        continue
                else:
                    line = input(PROMPT)
                # If the input is empty (i.e., 'Enter'), use the previous command
                if line:
                    last_command = line
                else:
                    line = last_command
            except EOFError:
                # Exit the REPL if there's nothing else to run.
                last_exc = asyncio.CancelledError()
                continue

            if not exec_repl_command(line, sys.stdout, dbg, driver, relay):
                last_exc = asyncio.CancelledError()
                continue

        elif isinstance(action, YieldExecDirect):
            if debug:
                print(
                    f"[-] REPL: Executing command '{action._command}' {'with' if action._capture else 'without'} output capture"
                )

            last_command = action._command

            if not action._prompt_silent:
                print(f"{PROMPT}{action._command}")

            try:
                if action._capture:
                    with TextIOWrapper(BytesIO(), write_through=True) as output:
                        should_continue = exec_repl_command(
                            action._command, output, dbg, driver, relay
                        )
                        last_result = output.buffer.getvalue()
                else:
                    should_continue = exec_repl_command(
                        action._command, sys.stdout, dbg, driver, relay
                    )
            except BaseException as e:
                last_exc = e
                continue

            if not should_continue:
                last_exc = asyncio.CancelledError()
                continue


def exec_repl_command(
    line: str,
    output_to,
    dbg: LLDB,
    driver: ProcessDriver,
    relay: EventRelay,
) -> bool:
    """
    Parses and runs the given command, returning whether the event loop should continue.
    """
    stdout = None
    stderr = None
    lldb_out = None
    lldb_err = None
    try:
        stdout = sys.stdout
        stderr = sys.stderr
        lldb_out = dbg.debugger.GetOutputFile()
        lldb_err = dbg.debugger.GetErrorFile()

        sys.stdout = output_to
        dbg.debugger.SetOutputFile(
            lldb.SBFile.Create(output_to, borrow=True, force_io_methods=True)
        )
        dbg.debugger.SetErrorFile(lldb.SBFile.Create(output_to, borrow=True, force_io_methods=True))

        return _exec_repl_command(line, output_to.buffer, dbg, driver, relay)
    finally:
        if stdout is not None:
            sys.stdout = stdout
        if stderr is not None:
            sys.stderr = stderr
        if lldb_out is not None:
            dbg.debugger.SetOutputFile(lldb_out)
        if lldb_err is not None:
            dbg.debugger.SetErrorFile(lldb_err)


def _exec_repl_command(
    line: str,
    lldb_out_target: BinaryIO,
    dbg: LLDB,
    driver: ProcessDriver,
    relay: EventRelay,
) -> bool:
    """
    Implementation for exec_repl_command
    """

    bits = lex_args(line)

    if len(line) == 0:
        return True

    # Let the user get an LLDB prompt if they so desire.
    if bits[0] == "lldb":
        print_warn("You are now entering LLDB mode. To exit, type 'quit', 'exit' or Ctrl-D.")
        print_warn(
            "In this mode, certain commands may cause Pwndbg to break. Proceed with caution."
        )
        dbg.debugger.RunCommandInterpreter(
            True, False, lldb.SBCommandInterpreterRunOptions(), 0, False, False
        )
        return True

    # Not allowed to have this be a regular command, because of LLDB.
    if "version".startswith(line) and line.startswith("ve"):
        pwndbg.commands.version.version_impl()
        return True

    # There are interactive commands that `SBDebugger.HandleCommand` will
    # silently ignore. We have to implement them manually, here.
    if "quit".startswith(line) and line.startswith("q"):
        return False
    if "exit".startswith(line) and line.startswith("exi"):
        return False

    # `script` is a little weird. Unlike with the other commands we're
    # emulating, we actually need LLDB to spawn it for it to make sense
    # from the perspective of the user. This means we have to make
    # special arrangements for it.
    #
    # There is a way to get LLDB to properly handle interactive commands,
    # and that is to start an interactive session with
    # `SBDebugger.RunCommandInterpreter`, but that comes with its own
    # challenges:
    #     (1) Starting an interactive session on standard input is the
    #         best option from the perspective of the user, as they get
    #         full access to the Python interpreter's readline functions.
    #         However, we can't start a session running a command, which
    #         means we open up the possibility of the user breaking
    #         Pwndbg completely if they type in any process or target
    #         management commands.
    #     (2) Setting an input file up for the debugger to use, having
    #         that input file start the Python interpreter, and piping
    #         `sys.stdin` to it while the interpreter is running. This
    #         option is better in that it avoids the possibility of the
    #         user breaking Pwndbg by mistake, but it breaks both
    #         readline and input in general for the user.
    #
    # While neither option is ideal, both can be partially mitigated.
    # Option (1) by adding an extra command that drops down to LLDB and
    # prints a warning to make the user aware of the risk of breaking
    # Pwndbg, and option (2) by making a TextIOBase class that uses input()
    # at the REPL level before piping that to the Python interpreter running
    # under LLDB.
    #
    # Currently, we go with the mitigated version of option (1), but option
    # (2) might still be on the table for the near future.
    #
    # Likewise for the other commands we barr here.
    found_barred = False
    for name, test in LLDB_EXCLUSIVE:
        if not test(bits[0]):
            continue

        print_error(
            f"The '{name}' command is not supported. Use the 'lldb' command to enter LLDB mode and try again."
        )

        found_barred = True

    if found_barred:
        return True

    # Because we need to capture events related to target setup and process
    # startup, we handle them here, in a special way.
    if bits[0].startswith("pr") and "process".startswith(bits[0]):
        if len(bits) > 1 and bits[1].startswith("la") and "launch".startswith(bits[1]):
            # This is `process launch`.
            process_launch(driver, relay, bits[2:], dbg)
            return True
        if len(bits) > 1 and bits[1].startswith("a") and "attach".startswith(bits[1]):
            # This is `process attach`.
            process_attach(driver, relay, bits[2:], dbg)
            return True
        if len(bits) > 1 and bits[1].startswith("conn") and "connect".startswith(bits[1]):
            # This is `process connect`.
            process_connect(driver, relay, bits[2:], dbg)
            return True
        # We don't care about other process commands..

    if (bits[0].startswith("at") and "attach".startswith(bits[0])) or (
        bits[0].startswith("_regexp-a") and "_regexp-attach".startswith(bits[0])
    ):
        # `attach` is an alias for `_regexp-attach`
        # (it is NOT an alias for `process attach` even if it may seem so!)
        attach(driver, relay, bits[1:], dbg)
        return True

    if bits[0].startswith("ta") and "target".startswith(bits[0]):
        if len(bits) > 1 and bits[1].startswith("c") and "create".startswith(bits[1]):
            # This is `target create`
            target_create(bits[2:], dbg)
            return True
        if len(bits) > 1 and bits[1].startswith("de") and "delete".startswith(bits[1]):
            # This is `target delete`
            #
            # Currently, this check is here but it does nothing. We might
            # need to check for this, but I can't figure out what kind of
            # processing we should do for its arguments, so we do nothing.
            pass

    if bits[0].startswith("r") and "run".startswith(bits[0]):
        # `run` is an alias for `process launch -X true --`
        process_launch(driver, relay, ["-X", "true", "--"] + bits[1:], dbg)
        return True

    if bits[0] == "c" or (bits[0].startswith("con") and "continue".startswith(bits[0])):
        # Handle `continue` manually. While `ProcessDriver.run_lldb_command`
        # is more than capable of handling this command itself, there's no
        # need for it to. We know what the user wants, so we can fast-track
        # their request.
        continue_process(driver, bits[1:], dbg)
        return True

    if bits[0].startswith("gd") and "gdb-remote".startswith(bits[0]):
        # `gdb-remote` is almost the same as `process launch -p gdb-remote`,
        # but it does some additional changes to the URL, by prepending
        # "connect://" to it. So, from our pespective, it is a separate
        # command, even though it will also end up calling process_launch().
        gdb_remote(driver, relay, bits[1:], dbg)
        return True

    if bits[0] == "set":
        # We handle `set` as a command override. We do this so that users
        # may change Pwndbg-specific settings in the same way that they
        # would in GDB Pwndbg.
        #
        # The alternatives to this are either (1) use a proper command,
        # but that requires the process to already be running, and needs us
        # to use a name other than "set", or (2) add our settings to the
        # standard debugger settings mechanism, like we do in GDB, but LLDB
        # doesn't support that.
        warn = False
        if len(bits) != 3:
            print("Usage: set <name> <value>")
            warn = True
        else:
            param = pget(bits[1])
            if param is None:
                print_error(f"unknown setting '{bits[1]}'")
                warn = True
            else:
                try:
                    pset(param, bits[2])
                except InvalidParse as e:
                    print_error(f"invalid value '{bits[2]}' for setting '{bits[1]}': {e}")
                    warn = True

        if warn:
            print_hint(
                "Use the 'config', 'theme' and 'help set' commands to see what settings are available."
            )
            print_hint(
                "Use the 'help set <name>' command to see information about a specific setting."
            )
            print_hint(
                "If you meant to change LLDB settings, use the fully spelled-out 'settings' command, instead."
            )

        return True

    if (
        (bits[0] == "h" or (bits[0].startswith("hel") and "help".startswith(bits[0])))
        and len(bits) >= 2
        and bits[1] == "set"
    ):
        # This is 'help set'
        #
        # We override this command to provide help for the 'set' command
        # override.
        warn = False
        if len(bits) > 3:
            print("Usage: help set [name]")
            warn = True
        elif len(bits) == 2:
            # In LLDB style, list all valid settings.
            print("Set a Pwndbg configuration parameter.")
            print()
            print("Syntax: set <name> <value>")
            for scope in pwndbg.lib.config.Scope:
                print()
                print(f"Configuration parameters - {scope._name_}:")
                pwndbg.commands.config.display_config("", scope, show_hints=False)
        else:
            # Show information about a single parameter.
            param = pget(bits[2])
            if param is None:
                print_error(f"unknown setting '{bits[2]}'")
                warn = True
            else:
                print(f"Set {param.set_show_doc}.")
                print()
                print(f"Syntax: set {param.name} <value>")
                print()
                if param.help_docstring:
                    print(param.help_docstring)

        if warn:
            print_hint("Use the 'help set' command to see what settings are available for Pwndbg.")
            print_hint(
                "If you meant to see help for LLDB settings, see the fully spelled-out 'settings' command, instead."
            )

        return True

    if bits[0] == "ipi":
        # Spawn IPython shell, easy for debugging
        run_ipython_shell()
        return True

    if (
        bits[0] == pwndbg.commands.start.entry.command_name
        or bits[0] in pwndbg.commands.start.entry.aliases
    ):
        # 'entry' is actually a Pwndbg command. For convenience, we launch the
        # process on its behalf, before letting it run.
        #
        # In the LLDB back-end, there is no proper mechanism to make a process
        # start from inside of a command, as there is in GDB. Ideally, we'd
        # rework `ProcessDriver` so that it lets us do that with an execution
        # controller, but that is quite a bit of work to fix a single command,
        # when using an override is enough to achieve the same goal.
        #
        # In any case, we should consider doing it if this proves to be too janky.
        if not driver.has_process():
            process_launch(driver, relay, ["-s"], dbg)

        # This intentionally falls through. We want LLDB to do the rest of the
        # work of processing 'entry'.

    # The command hasn't matched any of our filtered commands, just let LLDB
    # handle it normally. Either in the context of the process, if we have
    # one, or just in a general context.
    if driver.has_process():
        driver.run_lldb_command(line, lldb_out_target)
        dbg.relay_exceptions()
    else:
        ret = lldb.SBCommandReturnObject()
        dbg.debugger.GetCommandInterpreter().HandleCommand(line, ret)
        if ret.IsValid():
            # LLDB can give us strings that may fail to encode.
            out = ret.GetOutput().strip()
            if len(out) > 0:
                lldb_out_target.write(out.encode(sys.stdout.encoding, errors="backslashreplace"))
                lldb_out_target.write(b"\n")
            out = ret.GetError().strip()
            if len(out) > 0:
                lldb_out_target.write(out.encode(sys.stdout.encoding, errors="backslashreplace"))
                lldb_out_target.write(b"\n")
        dbg.relay_exceptions()

    # At this point, the last command might've queued up some execution
    # control procedures for us to chew on. Run them now.
    coroutine_fail_warn = False
    for process, coroutine in dbg.controllers:
        assert driver.has_process()
        assert driver.process.GetUniqueID() == process.process.GetUniqueID()

        try:
            driver.run_coroutine(coroutine)
        except Exception:
            # We treat exceptions coming from the execution controllers the
            # same way we treat exceptions coming from commands.
            pwndbg.exception.handle()
            coroutine_fail_warn = True

    dbg.controllers.clear()

    if coroutine_fail_warn:
        print_warn(
            "Exceptions occurred execution controller processing. Debugging will likely be unreliable going forward."
        )

    return True


def _bool_of_string(val: str) -> bool:
    """
    Convert a string to a boolean value.

    For use with ArgumentParser.
    """
    if val.lower() in ("true", "1", "yes"):
        return True
    elif val.lower() in ("false", "0", "no"):
        return False
    else:
        raise ValueError(f"{val} is not a recognized boolean value")


def parse(
    args: List[str],
    parser: argparse.ArgumentParser,
    unsupported: List[str],
    raw_marker: str | None = None,
) -> Any | None:
    """
    Parses a list of string arguments into an object containing the parsed
    data.

    If `raw_marker` is not `None`, the argument list will be split in
    two, with all arguments before the split being fed to the argument parser,
    and all arguments after the split being returned as-is. In this case the
    return value is a tuple.
    """
    raw = None
    if raw_marker is not None:
        # Always return something, even if we match nothing.
        raw = []

        try:
            index = args.index(raw_marker)
            raw = args[index + 1 :]
            args = args[:index]
        except ValueError:
            # Ugly, but avoids going over the list twice.
            pass

    try:
        args = parser.parse_args(args)
    except SystemExit:
        # Ugly, but need to keep ArgumentParser from terminating the process.
        return None

    # Reject any arguments we don't know how to handle yet.
    #
    # We'd like this list to grow over time, but we don't strictly need to
    # support all of these right away.
    varsargs = vars(args)
    for unsup in unsupported:
        if varsargs[unsup.replace("-", "_")]:
            print_error(f"Pwndbg does not support --{unsup} yet")
            return None

    if raw is not None:
        # If called with `raw_marked`, return a tuple.
        return args, raw

    return args


class AutoTarget:
    """
    During the execution of some commands, the LLDB CLI automatically creates an
    empty target and selects it before the command is executed.
    """

    def __init__(self, dbg: LLDB):
        self.error = lldb.SBError()
        self._dbg = dbg
        self._created_target = False

        count = dbg.debugger.GetNumTargets()
        if count == 0:
            # Create the target.
            self.target = dbg.debugger.CreateTarget(None, None, None, True, self.error)

            if not self.error.success:
                return

            # On success, select it and remember that it has been created.
            dbg.debugger.SetSelectedTarget(self.target)
            self._created_target = True
        elif count == 1:
            # Just use the current target.
            self.target = dbg.debugger.GetTargetAtIndex(0)
            assert self.target, f"SBDebugger::GetNumTargets() is 1, but SBDebugger::GetTargetAtIndex(0) is {self.target}"
        else:
            raise AssertionError(
                f"Pwndbg does not support multiple targets, so SBDebugger::GetNumTargets() must always be 0 or 1, but is {count}"
            )

    def __bool__(self):
        return self.error.success

    def close(self):
        if self._created_target:
            assert self._dbg.debugger.DeleteTarget(
                self.target
            ), "Could not delete the target we've just created. What?"


def run_ipython_shell():
    @contextmanager
    def switch_to_ipython_env():
        saved_excepthook = sys.excepthook
        try:
            saved_ps = sys.ps1, sys.ps2
        except AttributeError:
            saved_ps = None
        yield
        # Restore Python's default `ps1`, `ps2`, and `excepthook`
        # to ensure proper behavior of the LLDB `script` command.
        if saved_ps is not None:
            sys.ps1, sys.ps2 = saved_ps
        else:
            del sys.ps1
            del sys.ps2
        sys.excepthook = saved_excepthook

    def start_ipi():
        import IPython
        import jedi  # type: ignore[import-untyped]

        jedi.Interpreter._allow_descriptor_getattr_default = False
        IPython.embed(
            colors="neutral", banner1="", confirm_exit=False, simple_prompt=False, user_ns=globals()
        )

    with switch_to_ipython_env():
        start_ipi()


target_create_ap = argparse.ArgumentParser(add_help=False, prog="target create")
target_create_ap.add_argument("-S", "--sysroot")
target_create_ap.add_argument("-a", "--arch")
target_create_ap.add_argument("-b", "--build")
target_create_ap.add_argument("-c", "--core")
target_create_ap.add_argument("-d", "--no-dependents")
target_create_ap.add_argument("-p", "--platform")
target_create_ap.add_argument("-r", "--remote-file")
target_create_ap.add_argument("-s", "--symfile")
target_create_ap.add_argument("-v", "--version")
target_create_ap.add_argument("filename")
target_create_unsupported = [
    "build",
    "core",
    "no-dependents",
    "remote-file",
    "symfile",
    "version",
]


def _get_target_triple(debugger: lldb.SBDebugger, filepath: str) -> str | None:
    # The triple is the "architecture-vendor-OS[-ABI]" of the target binary.
    # Examples:
    # - "arm--linux-eabi"
    # - "aarch64--linux"
    # - "x86_64-apple-macosx11.7.0"
    # - "arm64-apple-macosx11.7.0"
    # - "aarch64-pc-windows-msvc"
    target: lldb.SBTarget = debugger.CreateTarget(filepath)
    if not target.IsValid():
        return None
    triple = target.triple
    debugger.DeleteTarget(target)
    return triple


def target_create(args: List[str], dbg: LLDB) -> None:
    """
    Creates a new target, registers it with the Pwndbg LLDB implementation, and
    sets up listeners for it.
    """
    args = parse(args, target_create_ap, target_create_unsupported)
    if not args:
        return

    if dbg.debugger.GetNumTargets() > 0:
        print_error(
            "Pwndbg does not support multiple targets. Please remove the current target with 'target delete' and try again."
        )
        return

    if args.platform and args.platform not in {"qemu-user"}:
        print_error("Pwndbg does currently support platforms: qemu-user")
        return

    if args.arch:
        dbg.debugger.SetDefaultArchitecture(args.arch)

    if args.sysroot:
        dbg.debugger.SetCurrentPlatformSDKRoot(args.sysroot)

    # Create the target with the debugger.
    error = lldb.SBError()
    if args.platform:
        dbg.debugger.SetCurrentPlatform(args.platform)

        # Having the platform specified requires that we specify the triple.
        triple = _get_target_triple(dbg.debugger, args.filename)
        if not triple:
            print_error(f"could not detect triple for '{args.filename}'")
            return

        if args.platform == "qemu-user":
            arch = triple.split("-")[0]
            # Without setting it qemu-user don't work ;(
            dbg._execute_lldb_command(f"settings set platform.plugin.qemu-user.architecture {arch}")

        target: lldb.SBTarget = dbg.debugger.CreateTarget(
            args.filename, triple, args.platform, True, error
        )
    else:
        # Let LLDB figure out both the triple and the platform automatically.
        target = dbg.debugger.CreateTarget(args.filename, None, None, True, error)
    if not error.success or not target.IsValid():
        print_error(f"could not create target for '{args.filename}': {error.description}")
        return

    dbg.debugger.SetSelectedTarget(target)
    print(f"Current executable set to '{args.filename}' ({target.triple.split('-')[0]})")
    return


process_launch_ap = argparse.ArgumentParser(add_help=False, prog="process launch")
process_launch_ap.add_argument("-A", "--disable-aslr", type=_bool_of_string, default=False)
process_launch_ap.add_argument("-C", "--script-class")
process_launch_ap.add_argument("-E", "--environment", action="append")
process_launch_ap.add_argument("-P", "--plugin")
process_launch_ap.add_argument("-X", "--shell-expand-args", type=_bool_of_string)
process_launch_ap.add_argument("-a", "--arch")
process_launch_ap.add_argument("-c", "--shell")
process_launch_ap.add_argument("-e", "--stderr")
process_launch_ap.add_argument("-i", "--stdin")
process_launch_ap.add_argument("-k", "--structured-data-key")
process_launch_ap.add_argument("-n", "--no-stdio")
process_launch_ap.add_argument("-o", "--stdout")
process_launch_ap.add_argument("-s", "--stop-at-entry", action="store_true")
process_launch_ap.add_argument("-t", "--tty")
process_launch_ap.add_argument("-v", "--structured-data-value")
process_launch_ap.add_argument("-w", "--working-dir")
process_launch_ap.add_argument("run-args", nargs="*")
process_launch_unsupported = [
    "script-class",
    "plugin",
    "arch",
    "shell",
    "stderr",
    "stdin",
    "structured-data-key",
    "no-stdio",
    "stdout",
    "tty",
    "structured-data-value",
    "working-dir",
]


def process_launch(driver: ProcessDriver, relay: EventRelay, args: List[str], dbg: LLDB) -> None:
    """
    Launches a process with the given arguments.
    """
    result = parse(args, process_launch_ap, process_launch_unsupported, raw_marker="--")
    if result is None:
        return
    args, raw = result

    launch_args = getattr(args, "run-args", []) + raw
    if args.shell_expand_args:
        # Perform shell expansion.
        launch_args = [os.path.expanduser(os.path.expandvars(arg)) for arg in launch_args]

    targets = dbg.debugger.GetNumTargets()
    assert targets < 2
    if targets == 0:
        print_error("no target, create one using the 'target create' command")
        return

    if driver.has_process():
        print_error("a process is already being debugged")
        return

    target: lldb.SBTarget = dbg.debugger.GetTargetAtIndex(0)

    # Make sure LLDB knows the correct remote or local status of this launch.
    dbg._current_process_is_gdb_remote = driver.has_connection()

    if target.GetPlatform().GetName() == "qemu-user":
        # Force qemu-user as remote, pwndbg depends on that, eg: for download procfs files
        dbg._current_process_is_gdb_remote = True

    io_driver = get_io_driver()
    result = driver.launch(
        target,
        io_driver,
        [f"{name}={value}" for name, value in os.environ.items()]
        + (args.environment if args.environment else []),
        launch_args,
        os.getcwd(),
        args.disable_aslr,
    )

    match result:
        case LaunchResultError(what, disconnected):
            print_error(f"could not launch process: {what.description}")
            if disconnected:
                print_warn("disconnected")
            return
        case LaunchResultEarlyExit():
            print_warn("process exited early")
            return

    # Continue execution if the user hasn't requested for a stop at the entry
    # point of the process. And handle necessary events.
    if not args.stop_at_entry:
        # The relay has already sended a START event at this point. Continuing
        # normally will send a CONTINUE event, which is incorrect, as START
        # already implies the program is about to start running. So we avoid
        # sending the next CONTINUE event.
        relay._set_ignore_resumed(1)

        driver.cont()
    else:
        # Tell the debugger that the process was suspended.
        #
        # The event system in the process driver can't natively represent the
        # START event type exactly. It knows only when a process has been
        # created and when a process changed it state to running from suspended,
        # and vice versa.
        #
        # This means that we have to relay an extra event here to convey that
        # the process stopped at entry, even though what's going on, in reality,
        # is that we're simply not resuming the process.
        dbg._trigger_event(EventType.STOP)


process_attach_ap = argparse.ArgumentParser(add_help=False, prog="process attach")
process_attach_ap.add_argument("-C", "--python-class")
process_attach_ap.add_argument("-P", "--plugin")
process_attach_ap.add_argument("-c", "--continue", action="store_true")
process_attach_ap.add_argument("-i", "--include-existing", action="store_true")
process_attach_ap.add_argument("-k", "--structured-data-key")
process_attach_ap.add_argument("-n", "--name")
process_attach_ap.add_argument("-p", "--pid", type=int)
process_attach_ap.add_argument("-v", "--structured-data-value")
process_attach_ap.add_argument("-w", "--waitfor", action="store_true")
process_attach_unsupported = [
    "python-class",
    "plugin",
    "structured-data-key",
    "structured-data-value",
]


def _attach_with_info(
    driver: ProcessDriver, relay: EventRelay, dbg: LLDB, info: lldb.SBAttachInfo, cont=False
):
    """
    Attaches to a process based on SBAttachInfo information
    """
    assert dbg.debugger.GetNumTargets() < 2

    # TODO/FIXME: This should ask:
    # 'There is a running process, detach from it and attach?: [Y/n]'
    if driver.has_process():
        print_error("a process is already being debugged")
        return

    auto = AutoTarget(dbg)
    if not auto:
        print_error(f"could not create empty target for attaching: {auto.error.description}")
        auto.close()
        return

    # Make sure LLDB knows the correct remote or local status of this attach.
    dbg._current_process_is_gdb_remote = driver.has_connection()

    result = driver.attach(
        auto.target,
        info,
    )

    match result:
        case LaunchResultError(what, disconnected):
            print_error(f"could not attach to process: {what.description}")
            if disconnected:
                print_warn("disconnected")
            auto.close()
            return
        case LaunchResultEarlyExit():
            print_warn("process exited early")
            auto.close()
            return

    # Continue execution if the user has requested it.
    if cont:
        # Same logic applies here as in `process_launch`.
        relay._set_ignore_resumed(1)
        driver.cont()
    else:
        # Same logic applies here as in `process_launch`.
        dbg._trigger_event(EventType.STOP)


def process_attach(driver: ProcessDriver, relay: EventRelay, args: List[str], dbg: LLDB) -> None:
    """
    Attaches to a process with the given arguments.
    """
    args = parse(args, process_attach_ap, process_attach_unsupported)
    if not args:
        return

    # The first two arguments - executable name and wait_for_launch - don't
    # matter, we set them later. The third one is required, as it tells LLDB the
    # attach should be asynchronous.
    info = lldb.SBAttachInfo(None, False, True)

    if args.name is not None:
        info.SetExecutable(args.name)
    if args.pid is not None:
        info.SetProcessID(args.pid)
    info.SetWaitForLaunch(args.waitfor)

    do_continue = getattr(args, "continue", False)
    if do_continue:
        info.SetResumeCount(1)
    info.SetIgnoreExisting(not args.include_existing)

    _attach_with_info(driver, relay, dbg, info, cont=do_continue)


def attach(driver: ProcessDriver, relay: EventRelay, args: List[str], dbg: LLDB) -> None:
    """
    Attaches to a process with the given name or pid based on regex match.
    Used for `_regexp-attach <pid|name>` (alias for `attach <pid|name>`)
    Note: for some reason, `attach` does not really take a regex for process name.
    """
    if len(args) != 1:
        print_error("expected 1 argument: <pid> or <name>")
        return
    arg = args[0]

    # exec name - None, we set it later (or pid)
    # wait_for_launch - False, since we don't wait
    # third arg - tell LLDB to attach asynchronously
    info = lldb.SBAttachInfo(None, False, True)

    # Argument is pid
    if arg.isdigit():
        info.SetProcessID(int(arg))
    else:
        info.SetExecutable(arg)

    _attach_with_info(driver, relay, dbg, info)


process_connect_ap = argparse.ArgumentParser(add_help=False, prog="process connect")
process_connect_ap.add_argument("-p", "--plugin")
process_connect_ap.add_argument("remoteurl")


def process_connect(driver: ProcessDriver, relay: EventRelay, args: List[str], dbg: LLDB) -> None:
    """
    Connects to the given remote process.
    """
    args = parse(args, process_connect_ap, [])
    if not args:
        return

    if "plugin" not in args or args.plugin != "gdb-remote":
        print_error(
            "Pwndbg only supports the gdb-remote plugin for 'process connect'. Please specify it with the '-p gdb-remote' argument."
        )
        return

    if driver.has_connection():
        print_error("debugger is already connected")
        return

    # Make sure the LLDB driver knows that this is a remote process.
    dbg._current_process_is_gdb_remote = True

    auto = AutoTarget(dbg)
    if not auto:
        print_error(f"could not create empty target for connection: {auto.error.description}")
        auto.close()
        return

    io_driver = get_io_driver()
    result = driver.connect(auto.target, io_driver, args.remoteurl, "gdb-remote")

    match result:
        case LaunchResultError(what, disconnected):
            print_error(f"could not connect to remote: {what.description}")
            if disconnected:
                print_warn("disconnected")
            auto.close()
            return
        case LaunchResultEarlyExit():
            print_warn("remote exited early")
            auto.close()
            return

    # Tell the debugger that the process was suspended, if there is a process.
    if driver.has_process():
        dbg._trigger_event(EventType.STOP)


gdb_remote_ap = argparse.ArgumentParser(add_help=False, prog="gdb-remote")
gdb_remote_ap.add_argument("remoteurl")


def gdb_remote(driver: ProcessDriver, relay: EventRelay, args: List[str], dbg: LLDB) -> None:
    """
    Like `process_connect`, but more lenient with the remote URL format.
    """

    args = parse(args, gdb_remote_ap, [])
    if not args:
        return

    parts = args.remoteurl.split(":")
    if len(parts) == 1:
        url = None
        port = parts[0]
    elif len(parts) == 2:
        url = parts[0]
        port = parts[1]
    else:
        print_error(f"unknown URL format '{args.remoteurl}'")
        return

    try:
        port = int(port, 10)
    except ValueError:
        print_error(f"could not interpret '{port}' as port number")
        return

    if url is None:
        print_warn("hostname not given, using 'localhost'")
        url = "localhost"

    process_connect(driver, relay, ["-p", "gdb-remote", f"connect://{url}:{port}"], dbg)


continue_ap = argparse.ArgumentParser(add_help=False, prog="continue")
continue_ap.add_argument("-i", "--ignore-count")
continue_unsupported = ["ignore-count"]


def continue_process(driver: ProcessDriver, args: List[str], dbg: LLDB) -> None:
    """
    Continues the execution of a process.
    """
    args = parse(args, continue_ap, continue_unsupported)
    if not args:
        return

    if not driver.has_process():
        print_error("no process")
        return

    driver.cont()
