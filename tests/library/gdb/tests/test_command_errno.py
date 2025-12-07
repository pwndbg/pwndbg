from __future__ import annotations

import gdb

from . import get_binary

# We use the heap_vis binary as it enforces pthreads and so will have TLS on all distros
REFERENCE_BINARY = get_binary("heap_vis.native.out")


def test_command_errno(start_binary):
    """
    Tests the errno command display
    """
    start_binary(REFERENCE_BINARY)

    gdb.execute("break main")
    gdb.execute("continue")

    result = gdb.execute("errno", to_string=True)
    assert result == "Errno 0: OK\n"

    gdb.execute("set *(int*)&errno=11")
    result = gdb.execute("errno", to_string=True)
    assert result == "Errno 11: EAGAIN\n"

    gdb.execute("set *(int*)&errno=111")
    result = gdb.execute("errno", to_string=True)
    assert result == "Errno 111: ECONNREFUSED\n"

    result = gdb.execute("errno 8", to_string=True)
    assert result == "Errno 8: ENOEXEC\n"

    result = gdb.execute("errno 123", to_string=True)
    assert result == "Errno 123: ENOMEDIUM\n"

    result = gdb.execute("errno 250", to_string=True)
    assert result == "Errno 250: Unknown error code\n"
