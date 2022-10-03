import re

import gdb

import pwndbg.commands
import tests

USE_FDS_BINARY = tests.binaries.get("use-fds.out")


def test_context_disasm_show_fd_filepath(start_binary):
    """
    Tests context disasm command and whether it shows properly opened fd filepath
    """
    start_binary(USE_FDS_BINARY)

    # Run until main
    gdb.execute("break main")
    gdb.execute("continue")

    # Stop on read(0, ...) -> should show /dev/pts/X or pipe:X on CI
    gdb.execute("nextcall")

    out = pwndbg.commands.context.context_disasm()
    assert "[ DISASM / x86-64 / set emulate on ]" in out[0]  # Sanity check

    call_read_line_idx = out.index(next(line for line in out if "<read@plt>" in line))
    lines_after_call_read = out[call_read_line_idx:]

    line_call_read, line_fd, line_buf, line_nbytes, *_rest = lines_after_call_read

    assert "call   read@plt" in line_call_read

    line_fd = line_fd.strip()
    assert re.match(r"fd:\s+0x1 \((/dev/pts/\d+|pipe:\[\d+\])\)", line_fd)

    line_buf = line_buf.strip()
    assert re.match(r"buf:\s+0x[0-9a-f]+ ◂— 0x0", line_buf)

    line_nbytes = line_nbytes.strip()
    assert re.match(r"nbytes:\s+0x0", line_nbytes)

    # Stop on open(...)
    gdb.execute("nextcall")
    # Stop on read(...) -> should show use-fds.out
    gdb.execute("nextcall")

    out = pwndbg.commands.context.context_disasm()
    assert "[ DISASM / x86-64 / set emulate on ]" in out[0]  # Sanity check

    call_read_line_idx = out.index(next(line for line in out if "<read@plt>" in line))
    lines_after_call_read = out[call_read_line_idx:]

    line_call_read, line_fd, line_buf, line_nbytes, *_rest = lines_after_call_read

    line_fd = line_fd.strip()
    assert re.match(r"fd:\s+0x3 \([a-z/]*pwndbg/tests/binaries/use-fds.out\)", line_fd)

    line_buf = line_buf.strip()
    assert re.match(r"buf:\s+0x[0-9a-f]+ ◂— 0x0", line_buf)

    line_nbytes = line_nbytes.strip()
    assert re.match(r"nbytes:\s+0x10", line_nbytes)
