import re

import gdb
import pytest

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

    # When running tests with GNU Parallel, sometimes the file name looks
    # '/tmp/parZ4YC4.par', and occasionally '(deleted)' is present after the
    # filename
    line_fd = line_fd.strip()
    assert re.match(
        r"fd:\s+0x1 \((/dev/pts/\d+|/tmp/par.+\.par(?: \(deleted\))?|pipe:\[\d+\])\)", line_fd
    )

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
    assert re.match(
        r"fd:\s+0x3 \([a-z/]*pwndbg/tests/gdb-tests/tests/binaries/use-fds.out\)", line_fd
    )

    line_buf = line_buf.strip()
    assert re.match(r"buf:\s+0x[0-9a-f]+ ◂— 0x0", line_buf)

    line_nbytes = line_nbytes.strip()
    assert re.match(r"nbytes:\s+0x10", line_nbytes)


@pytest.mark.parametrize("sections", ("''", '""', "none", "-", ""))
def test_empty_context_sections(start_binary, sections):
    start_binary(USE_FDS_BINARY)

    # Sanity check
    default_ctx_sects = "regs disasm code ghidra stack backtrace expressions"
    assert pwndbg.gdblib.config.context_sections.value == default_ctx_sects
    assert gdb.execute("context", to_string=True) != ""

    # Actual test check
    gdb.execute(f"set context-sections {sections}", to_string=True)
    assert pwndbg.gdblib.config.context_sections.value == ""
    assert gdb.execute("context", to_string=True) == ""

    # Bring back old values && sanity check
    gdb.execute(f"set context-sections {default_ctx_sects}")
    assert pwndbg.gdblib.config.context_sections.value == default_ctx_sects
    assert gdb.execute("context", to_string=True) != ""
