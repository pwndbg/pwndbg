"""
The abstracted debugger interface.
"""

from __future__ import annotations

from typing import Any
from typing import Callable
from typing import Tuple

dbg: Debugger = None

class Session:
    """
    Interactive debugger session. Handles things like commands and history.
    """
    
    def history(self) -> list[str]:
        """
        The command history of this interactive session.
        """
        raise NotImplementedError()
    
    def lex_args(self, command_line: str) -> list[str]:
        """
        Lexes the given command line into a list of arguments, according to the
        conventions of the debugger being used and of the interactive session.
        """
        raise NotImplementedError()

class CommandHandle:
    """
    An opaque handle to an installed command.
    """
    def remove(self) -> None:
        """
        Removes this command from the command palette of the debugger.
        """
        raise NotImplementedError()

class Debugger:
    """
    The base class representing a debugger.
    """

    def setup(self, *args: Any) -> None:
        """
        Perform debugger-specific initialization.

        Because we can't really know what a given debugger object will need as
        part of its setup process, we allow for as many arguments as desired to
        be passed in, and leave it up to the implementations to decide what they
        need.

        This shouldn't be a problem, seeing as, unlike other methods in this
        class, this should only be called as part of the debugger-specific
        bringup code.
        """
        raise NotImplementedError()

    def session(self) -> Session | None:
        """
        Returns a reference to the interactive session associated with this
        debugger, if any.
        """
        raise NotImplementedError()

    def add_command(self, name: str, handler: Callable[str, bool]) -> CommandHandle:
        """
        Adds a command with the given name to the debugger, that invokes the
        given function every time it is called.
        """
        raise NotImplementedError()

    # WARNING
    #
    # These are hacky parts of the API that were strictly necessary to bring up
    # pwndbg under LLDB without breaking it under GDB. Expect most of them to be
    # removed or replaced as the porting work continues.
    # 

    def addrsz(self, address: Any) -> str:
        """
        Format the given address value.
        """
        raise NotImplementedError()

    def get_cmd_window_size(self) -> Tuple[int, int]:
        """
        The size of the command window, in characters, if available.
        """
        raise NotImplementedError()

    def set_python_diagnostics(self, enabled: bool) -> None:
        """
        Enables or disables Python diagnostic messages for this debugger.
        """
        raise NotImplementedError()
