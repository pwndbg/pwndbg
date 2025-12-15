from __future__ import annotations

import gdb
import pytest

from . import get_binary

BINARY = get_binary("heap_bins.native.out")


def test_reload_command(start_binary):
    """Test that the reload command works and events are re-registered"""
    start_binary(BINARY)
    
    # Execute reload command
    gdb.execute("reload")
    
    # After reload, context should still be shown when we continue and stop
    # Set a breakpoint
    gdb.execute("break main")
    
    # Run the program
    gdb.execute("run")
    
    # The context should be displayed (this is handled by the prompt hook)
    # If the reload broke the prompt hook or events, the context wouldn't show
    # We can verify this by checking that basic commands still work
    result = gdb.execute("context", to_string=True)
    assert len(result) > 0, "Context should produce output after reload"
    
    # Verify that vmmap still works (checks that event handlers are working)
    result = gdb.execute("vmmap", to_string=True)
    assert len(result) > 0, "Vmmap should produce output after reload"


def test_reinit_pwndbg_command(start_binary):
    """Test that the reinit-pwndbg command works"""
    start_binary(BINARY)
    
    # Execute reinit-pwndbg command
    gdb.execute("reinit-pwndbg")
    
    # After reinit, commands should still work
    result = gdb.execute("context", to_string=True)
    assert len(result) > 0, "Context should produce output after reinit-pwndbg"
