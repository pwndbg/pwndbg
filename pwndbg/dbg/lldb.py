
import lldb

import pwndbg.dbg

class LLDB(pwndbg.dbg.Debugger):
    def setup(self, *args):
        debugger = args[0]
        assert debugger.__class__ is lldb.SBDebugger, \
            "lldbinit.py should call setup() with an lldb.SBDebugger object"
   
        self.debugger = debugger


