"""
For our REPL, we need to drive our own I/O with the process being debugged. This
module contains all the strategies we have for doing that.
"""

from __future__ import annotations

import os
import sys
import threading
from typing import Tuple

import lldb
from typing_extensions import override

from pwndbg.dbg.lldb.util import system_decode

if os.name == "posix":
    # We use select for files when not on POSIX. Additionally, we support pseudo
    # terminal devices under POSIX.
    import ctypes
    import select
    import signal
    import termios

    TERM_CONTROL_AVAILABLE = True
    SELECT_AVAILABLE = True
    PTY_AVAILABLE = True
else:
    # We sleep for a little bit when we don't have select.
    import time

    TERM_CONTROL_AVAILABLE = False
    SELECT_AVAILABLE = False
    PTY_AVAILABLE = False


# This is documented in Python's termios module, under tcgetattr, but, for some
# reason, there's no constant for it.
TC_LFLAG = 3


class OpportunisticTerminalControl:
    """
    Handles optional terminal control for a given file descriptor. Crucially,
    all the functions in this class should work regardless of whether terminal
    control is actually supported on not, but should do nothing in case it is
    not supported.
    """

    fd: int
    supported: bool

    def __init__(self, fd: int = -1):
        """
        Creates an opportunistic terminal control object for the given file
        descriptor. If no file descriptor is given, this class will try to open
        '/dev/tty', and use that.
        """
        if not TERM_CONTROL_AVAILABLE:
            # Preemptively disable this class if terminal control isn't possible
            # in this target, and do nothing else.
            self.supported = False
            return

        if fd == -1:
            try:
                fd = os.open("/dev/tty", os.O_RDWR)
            except (FileNotFoundError, PermissionError):
                # Flop and die.
                self.supported = False
                return

        self.fd = fd

        # Query for basic support for this file descriptor by querying its
        # attributes. If that fails, we assume the file descriptor we were
        # given does not support terminal control.
        try:
            termios.tcgetattr(fd)
            self.supported = True
        except termios.error:
            self.supported = False

    def _getattrbits(self, attri: int, mask: int) -> int:
        """
        Returns the result of applying the given bitmask to the given index in
        the array returned by termios.tcgetattr.
        """
        attr = termios.tcgetattr(self.fd)
        return attr[attri] & mask

    def _setattrbits(self, attri: int, mask: int, value: int) -> None:
        """
        Modifies the attribute integer at the given index in the array returned
        by termios.tcgetattr, then sets the terminal attributes to the resulting
        value.

        The new attribute integer will look like `(attr & ~mask) | value`.
        """
        attr = termios.tcgetattr(self.fd)
        attr[attri] = (attr[attri] & ~mask) | value
        termios.tcsetattr(self.fd, termios.TCSANOW, attr)

    def get_line_buffering(self) -> bool:
        """
        Gets the current state of line buffering for this terminal.
        """
        if not self.supported:
            return True
        return self._getattrbits(TC_LFLAG, termios.ICANON) != 0

    def set_line_buffering(self, enabled: bool) -> None:
        """
        Enables or disables line buffering for this terminal.
        """
        if not self.supported:
            return
        self._setattrbits(TC_LFLAG, termios.ICANON, termios.ICANON if enabled else 0)

    def get_echo(self) -> bool:
        """
        Gets the current state of echoing for this terminal.
        """
        if not self.supported:
            return True
        return self._getattrbits(TC_LFLAG, termios.ECHO) != 0

    def set_echo(self, enabled: bool) -> None:
        """
        Enables or disables echoing for this terminal.
        """
        if not self.supported:
            return
        self._setattrbits(TC_LFLAG, termios.ECHO, termios.ECHO if enabled else 0)


class IODriver:
    def stdio(self) -> Tuple[str | None, str | None, str | None]:
        """
        The names for the stdin, stdout and stderr files, respectively. These
        will get passed as arguments to `SBTarget.Launch`
        """
        raise NotImplementedError()

    def start(self, process: lldb.Process) -> None:
        """
        Starts the handling of I/O by this driver on the given process.
        """
        raise NotImplementedError()

    def stop(self) -> None:
        """
        Stops the handling of I/O by this driver.
        """
        raise NotImplementedError()

    def on_output_event(self) -> None:
        """
        Hints that there might be data in either the standard output or the
        standard error streams. This should be called when an
        `eBroadcastBitSTDOUT` or `eBroadcastBitSTDERR` is encountered by the
        event loop.
        """
        raise NotImplementedError()

    def on_process_start(self, proc: lldb.SBProcess) -> None:
        """
        Allow the I/O driver an opportunity to change aspects of the process
        after it has been launched, but before it has started executing, if it
        so wishes.
        """
        raise NotImplementedError()


def get_io_driver() -> IODriver:
    """
    Instances a new IODriver using the best strategy available in the current
    system. Meaning a PTY on Unix and plain text on Windows.
    """
    if PTY_AVAILABLE:
        pty = make_pty()
        if pty is not None:
            worker, manager = pty
            return IODriverPseudoTerminal(worker=worker, manager=manager)
    return IODriverPlainText()


class IODriverPlainText(IODriver):
    """
    Plaintext-based I/O driver. It simply copies input from our standard input
    to the standard input of a given process, and copies output from the standard
    output of a given process to out standard output.
    """

    likely_output: threading.BoundedSemaphore
    in_thr: threading.Thread
    out_thr: threading.Thread
    stop_requested: threading.Event

    process: lldb.SBProcess

    def __init__(self):
        self.likely_output = threading.BoundedSemaphore(1)
        self.process = None
        self.stop_requested = threading.Event()

    @override
    def stdio(self) -> Tuple[str | None, str | None, str | None]:
        return None, None, None

    def _handle_input(self):
        while not self.stop_requested.is_set():
            if SELECT_AVAILABLE:
                select.select([sys.stdin], [], [], 0.2)

            try:
                data = sys.stdin.read()
                self.process.PutSTDIN(data)
            except (BlockingIOError, TypeError):
                # We have to check for TypeError here too, as, even though you
                # *can* set stdin into nonblocking mode, it doesn't handle it
                # very gracefully.
                #
                # See https://github.com/python/cpython/issues/57531

                # Ignore blocking errors, but wait for a little bit before
                # trying again if we don't have select().
                if not SELECT_AVAILABLE:
                    time.sleep(0.1)

    def _handle_output(self):
        while not self.stop_requested.is_set():
            # Try to acquire the semaphore. This will not succeed until the next
            # process output event is received by the event loop.
            self.likely_output.acquire(timeout=0.2)

            # Don't actually stop ourselves, even if we can't acquire the
            # semaphore. LLDB can be a little lazy with the standard output
            # events, so we use the semaphore as way to respond much faster to
            # output than we otherwise would, but, even if we don't get an
            # event, we should still read the output, albeit at a slower pace.

            # Copy everything out to standard outputs.
            while True:
                stdout = self.process.GetSTDOUT(1024)
                stderr = self.process.GetSTDERR(1024)

                if len(stdout) == 0 and len(stderr) == 0:
                    break

                print(stdout, file=sys.stdout, end="")
                print(stderr, file=sys.stderr, end="")

                sys.stdout.flush()
                sys.stderr.flush()

            # Crutially, we don't release the semaphore here. Releasing is the
            # job of the on_output_event function.

    @override
    def on_output_event(self) -> None:
        try:
            self.likely_output.release()
        except ValueError:
            # We haven't responded to the previous event yet. No matter, when
            # the output handler gets around to it, all the output from the
            # previous events will get processed.
            #
            # All that matters is that the output handler knows there's *some*
            # data to process.
            pass

    @override
    def on_process_start(self, proc: lldb.SBProcess) -> None:
        # We don't really want to do anything on process start.
        pass

    @override
    def start(self, process: lldb.Process) -> None:
        # Set up new threads and start processing I/O.
        assert self.process is None, "Multiple calls to start()"
        self.process = process
        self.stop_requested.clear()
        os.set_blocking(sys.stdin.fileno(), False)
        self.in_thr = threading.Thread(target=self._handle_input)
        self.out_thr = threading.Thread(target=self._handle_output)
        self.in_thr.start()
        self.out_thr.start()

    @override
    def stop(self) -> None:
        # Politely ask for the I/O processors to stop, and wait until they have
        # stopped on their own terms.
        self.stop_requested.set()
        self.in_thr.join()
        self.out_thr.join()
        os.set_blocking(sys.stdin.fileno(), True)
        self.process = None


def make_pty() -> Tuple[str, int] | None:
    """
    We need to make a pseudo-terminal ourselves if we want the process to handle
    naturally for the user. Returns a tuple with the path of the worker device
    and the file descriptor of the manager device if successful.
    """
    # These functions are only part of the Python Standard Library starting in
    # Python 3.13, so we can't do much better than this, unfortunately.
    try:
        if sys.platform == "linux":
            libc = ctypes.CDLL("libc.so.6")
            # O_RWDR | O_NOCTTY = 0x102
            pty = libc.posix_openpt(0x102)
        elif sys.platform == "darwin":
            libc = ctypes.CDLL("libSystem.B.dylib")
            # O_RWDR | O_NOCTTY = 0x131072
            pty = libc.posix_openpt(0x131072)
        else:
            # Not supported.
            return None
    except OSError:
        # Not supported.
        return None

    if pty <= 0:
        return None

    libc.ptsname.restype = ctypes.c_char_p
    name = libc.ptsname(pty)

    if libc.unlockpt(pty) != 0:
        libc.close(pty)
        return None

    try:
        name = system_decode(name)
    except UnicodeDecodeError:
        # The name of the terminal device is nonsensical to us, so we can't use
        # this PTY. Warn the user that getting the PTY has failed.
        print(f"warning: cannot interpret ptsname {name} as a string. not using a pseudo-terminal")
        return None

    return name, pty


LIVE_PSEUDO_TERMINAL_OBJECTS = False


class IODriverPseudoTerminal(IODriver):
    """
    pty-based I/O driver. Forwards input from standard input and has support for
    terminal width and height, and for terminal-based file operations on the
    program being debugged.
    """

    manager: int
    worker: str
    stop_requested: threading.Event
    input_buffer: bytes
    io_thread: threading.Thread
    process: lldb.SBProcess
    termcontrol: OpportunisticTerminalControl

    has_terminal_control: bool

    def __init__(self, manager: int, worker: str):
        assert (
            PTY_AVAILABLE
        ), "IODriverPseudoTerminal should never be created unless PTY_AVAILABLE is set"

        global LIVE_PSEUDO_TERMINAL_OBJECTS
        LIVE_PSEUDO_TERMINAL_OBJECTS = True

        self.manager = manager
        self.worker = worker

        # Try to set up our opportunistic control of the input terminal.
        self.termcontrol = OpportunisticTerminalControl()
        if not self.termcontrol.supported:
            print("warning: could not set up terminal control")

        # Put the manager in nonblocking mode.
        os.set_blocking(self.manager, False)

        # We could support querying the terminal size in older versions of Python,
        # too, but, for now, this should be good enough.
        #
        # TODO: Properly support terminal size queries in Python 3.10 and older.
        # Handle terminal resizes.
        if sys.version_info >= (3, 11):
            # The way we currently handle terminal resizing absolutely does not
            # support multipleinstances of IODriverPseudoTerminal, but we
            # shouldn't have more than one object live at a time anyway for the
            # REPL, so this is fine.
            try:
                terminal = open("/dev/tty", "rb")

                def handle_sigwinch(_sig, _frame):
                    # Tell vermin to ignore these. This block is
                    # gated behind Python 3.11.
                    size = termios.tcgetwinsize(terminal.fileno())  # novm
                    termios.tcsetwinsize(self.manager, size)  # novm

                signal.signal(signal.SIGWINCH, handle_sigwinch)
            except FileNotFoundError:
                print(
                    "warning: no terminal device in /dev/tty, expect no support for terminal sizes"
                )

        self.stop_requested = threading.Event()
        self.input_buffer = b""
        self.process = None

    @override
    def stdio(self) -> Tuple[str | None, str | None, str | None]:
        return self.worker, self.worker, self.worker

    def _handle_io(self):
        while not self.stop_requested.is_set():
            select.select([sys.stdin, self.manager], [self.manager], [], 0.2)

            try:
                while True:
                    data = os.read(sys.stdin.fileno(), 1024)
                    if len(data) == 0:
                        break
                    self.input_buffer += data
            except IOError:
                pass

            try:
                written = os.write(self.manager, self.input_buffer)
                self.input_buffer = self.input_buffer[written:]
            except IOError:
                pass

            try:
                while True:
                    data = os.read(self.manager, 1024)
                    if len(data) == 0:
                        break
                    print(data.decode("utf-8"), end="")
                    sys.stdout.flush()
            except IOError:
                pass

    @override
    def start(self, process: lldb.Process) -> None:
        # Set up new threads and start processing I/O.
        assert self.process is None, "Multiple calls to start()"
        self.process = process
        self.stop_requested.clear()
        os.set_blocking(sys.stdin.fileno(), False)

        self.was_line_buffering = self.termcontrol.get_line_buffering()
        self.was_echoing = self.termcontrol.get_echo()

        self.termcontrol.set_line_buffering(False)
        self.termcontrol.set_echo(False)

        self.io_thread = threading.Thread(target=self._handle_io)
        self.io_thread.start()

    @override
    def stop(self) -> None:
        # Politely ask for the I/O processors to stop, and wait until they have
        # stopped on their own terms.
        self.stop_requested.set()
        self.io_thread.join()
        os.set_blocking(sys.stdin.fileno(), True)

        self.termcontrol.set_line_buffering(self.was_line_buffering)
        self.termcontrol.set_echo(self.was_echoing)

        self.process = None

    @override
    def on_output_event(self) -> None:
        # We drive our output ourselves.
        pass

    @override
    def on_process_start(self, proc: lldb.SBProcess) -> None:
        # Once we have `pwndbg.gdblib.shellcode` functioning, we could try to
        # attempt a "coup" of the controlling TTY for the process, here, so we
        # get to have the PTY we set up in this class as the main controller for
        # this process.
        #
        # TODO: Replace controlling PTY of the process once it is set up.
        pass
