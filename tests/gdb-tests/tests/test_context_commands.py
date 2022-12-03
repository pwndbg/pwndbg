import re

import gdb
import pytest

import pwndbg.commands
import tests

USE_FDS_BINARY = tests.binaries.get("use-fds.out")
TABSTOP_BINARY = tests.binaries.get("tabstop.out")
SYSCALLS_BINARY = tests.binaries.get("syscalls-x64.out")


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


def test_source_code_tabstop(start_binary):
    start_binary(TABSTOP_BINARY)

    # Run until line 6
    gdb.execute("break tabstop.c:6")
    gdb.execute("continue")

    # Default context-source-code-tabstop = 8
    src = gdb.execute("context code", to_string=True)
    assert """ 1 #include <stdio.h>\n""" in src
    assert """ 2 \n""" in src
    assert """ 3 int main() {\n""" in src
    assert """ 4         // test mix indent\n""" in src
    assert """ 5         do {\n""" in src
    assert """ 6                 puts("tab line");\n""" in src
    assert """ 7         } while (0);\n""" in src
    assert """ 8         return 0;\n""" in src
    assert """ 9 }\n""" in src
    assert """10 \n""" in src

    # Test context-source-code-tabstop = 2
    gdb.execute("set context-source-code-tabstop 2")
    src = gdb.execute("context code", to_string=True)
    assert """ 1 #include <stdio.h>\n""" in src
    assert """ 2 \n""" in src
    assert """ 3 int main() {\n""" in src
    assert """ 4   // test mix indent\n""" in src
    assert """ 5         do {\n""" in src
    assert """ 6     puts("tab line");\n""" in src
    assert """ 7         } while (0);\n""" in src
    assert """ 8         return 0;\n""" in src
    assert """ 9 }\n""" in src
    assert """10 \n""" in src

    # Disable context-source-code-tabstop
    gdb.execute("set context-source-code-tabstop 0")
    src = gdb.execute("context code", to_string=True)
    assert """ 1 #include <stdio.h>\n""" in src
    assert """ 2 \n""" in src
    assert """ 3 int main() {\n""" in src
    assert """ 4 \t// test mix indent\n""" in src
    assert """ 5         do {\n""" in src
    assert """ 6 \t\tputs("tab line");\n""" in src
    assert """ 7         } while (0);\n""" in src
    assert """ 8         return 0;\n""" in src
    assert """ 9 }\n""" in src
    assert """10 \n""" in src


def test_context_disasm_syscalls_args_display(start_binary):
    start_binary(SYSCALLS_BINARY)
    gdb.execute("nextsyscall")
    dis = gdb.execute("context disasm", to_string=True)
    assert dis == (
        "LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA\n"
        "──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────\n"
        "   0x400080 <_start>       mov    eax, 0\n"
        "   0x400085 <_start+5>     mov    edi, 0x1337\n"
        "   0x40008a <_start+10>    mov    esi, 0xdeadbeef\n"
        "   0x40008f <_start+15>    mov    ecx, 0x10\n"
        " ► 0x400094 <_start+20>    syscall  <SYS_read>\n"
        "        fd:        0x1337\n"
        "        buf:       0xdeadbeef\n"
        "        nbytes:    0x0\n"
        "   0x400096 <_start+22>    mov    eax, 0xa\n"
        "   0x40009b <_start+27>    int    0x80\n"
        "   0x40009d                add    byte ptr [rax], al\n"
        "   0x40009f                add    byte ptr [rax], al\n"
        "   0x4000a1                add    byte ptr [rax], al\n"
        "   0x4000a3                add    byte ptr [rax], al\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    gdb.execute("nextsyscall")
    dis = gdb.execute("context disasm", to_string=True)
    assert dis == (
        "LEGEND: STACK | HEAP | CODE | DATA | RWX | RODATA\n"
        "──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────\n"
        "   0x400085 <_start+5>     mov    edi, 0x1337\n"
        "   0x40008a <_start+10>    mov    esi, 0xdeadbeef\n"
        "   0x40008f <_start+15>    mov    ecx, 0x10\n"
        "   0x400094 <_start+20>    syscall \n"
        "   0x400096 <_start+22>    mov    eax, 0xa\n"
        " ► 0x40009b <_start+27>    int    0x80 <SYS_unlink>\n"
        "        name:      0x1337\n"
        "   0x40009d                add    byte ptr [rax], al\n"
        "   0x40009f                add    byte ptr [rax], al\n"
        "   0x4000a1                add    byte ptr [rax], al\n"
        "   0x4000a3                add    byte ptr [rax], al\n"
        "   0x4000a5                add    byte ptr [rax], al\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )
