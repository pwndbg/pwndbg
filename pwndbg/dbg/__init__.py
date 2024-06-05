"""
The abstracted debugger interface.
"""

from __future__ import annotations

dbg = None


class Debugger:
    """
    The base class
    """

    def setup(self, *args):
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

    # WARNING
    #
    # These are hacky parts of the API that were strictly necessary to bring up
    # pwndbg under LLDB without breaking it under GDB. Expect most of them to be
    # removed or replaced as the porting work continues.
    #

    def addrsz(self, address):
        """
        Format the given address value.
        """
        raise NotImplementedError()

    def get_cmd_window_size(self):
        """
        The size of the command window, in characters, if available.
        """
        raise NotImplementedError()

    def set_python_diagnostics(self, enabled):
        """
        Enables or disables Python diagnostic messages for this debugger.
        """
        raise NotImplementedError()
