from __future__ import annotations

import gdb

import tests

# We use the heap_vis binary as it enforces pthreads and so will have TLS on all distros
REFERENCE_BINARY = tests.binaries.get("heap_vis.out")


def test_command_errno(start_binary):
    """
    Tests the errno command display
    """
    start_binary(REFERENCE_BINARY)

    # Since start_binary does 'starti' which stops on the very first instruction
    # the errno is not yet an available symbol, because the libc library it is
    # defined in is not yet loaded
    result = "".join(gdb.execute("errno", to_string=True).splitlines())
    assert (
        result
        == "Could not determine error code automatically: neither `errno` nor `__errno_location` symbols were provided (perhaps libc.so hasn't been not loaded yet?)"
    )

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
