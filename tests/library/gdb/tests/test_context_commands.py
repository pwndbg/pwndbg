from __future__ import annotations

import re

import gdb
import pytest

import pwndbg.aglib.memory
import pwndbg.aglib.regs
import pwndbg.commands
import pwndbg.commands.canary
import pwndbg.commands.context
import tests

REFERENCE_BINARY = tests.binaries.get("reference-binary.out")
USE_FDS_BINARY = tests.binaries.get("use-fds.out")
TABSTOP_BINARY = tests.binaries.get("tabstop.out")
SYSCALLS_BINARY = tests.binaries.get("syscalls-x64.out")
MANGLING_BINARY = tests.binaries.get("symbol_1600_and_752.out")


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
        r"fd:\s+1 \((/dev/pts/\d+|/tmp/par.+\.par(?: \(deleted\))?|pipe:\[\d+\])\)", line_fd
    )

    line_buf = line_buf.strip()
    assert re.match(r"buf:\s+0x[0-9a-f]+ ◂— 0", line_buf)

    line_nbytes = line_nbytes.strip()
    assert re.match(r"nbytes:\s+0", line_nbytes)

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
        r"fd:\s+3 \([a-z/]*pwndbg/tests/gdb-tests/tests/binaries/use-fds.out\)", line_fd
    )

    line_buf = line_buf.strip()
    assert re.match(r"buf:\s+0x[0-9a-f]+ ◂— 0", line_buf)

    line_nbytes = line_nbytes.strip()
    assert re.match(r"nbytes:\s+0x10", line_nbytes)


@pytest.mark.parametrize("sections", ("''", '""', "none", "-", ""))
def test_empty_context_sections(start_binary, sections):
    start_binary(USE_FDS_BINARY)

    # Sanity check
    default_ctx_sects = "regs disasm code ghidra stack backtrace expressions threads heap_tracker"
    assert pwndbg.config.context_sections.value == default_ctx_sects
    assert gdb.execute("context", to_string=True) != ""

    # Actual test check
    gdb.execute(f"set context-sections {sections}", to_string=True)
    assert pwndbg.config.context_sections.value == ""
    assert gdb.execute("context", to_string=True) == ""

    # Bring back old values && sanity check
    gdb.execute(f"set context-sections {default_ctx_sects}")
    assert pwndbg.config.context_sections.value == default_ctx_sects
    assert gdb.execute("context", to_string=True) != ""


def test_source_code_tabstop(start_binary):
    start_binary(TABSTOP_BINARY)

    # Run until line 6
    gdb.execute("break tabstop.c:6")
    gdb.execute("continue")

    # Default context-code-tabstop = 8
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

    # Test context-code-tabstop = 2
    gdb.execute("set context-code-tabstop 2")
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

    # Disable context-code-tabstop
    gdb.execute("set context-code-tabstop 0")
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
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────\n"
        "   0x400080 <_start>       mov    eax, 0                 EAX => 0\n"
        "   0x400085 <_start+5>     mov    edi, 0x1337            EDI => 0x1337\n"
        "   0x40008a <_start+10>    mov    esi, 0xdeadbeef        ESI => 0xdeadbeef\n"
        "   0x40008f <_start+15>    mov    ecx, 0x10              ECX => 0x10\n"
        " ► 0x400094 <_start+20>    syscall  <SYS_read>\n"
        "        fd:        0x1337\n"
        "        buf:       0xdeadbeef\n"
        "        nbytes:    0\n"
        "   0x400096 <_start+22>    mov    eax, 0xa               EAX => 0xa\n"
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
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────\n"
        "   0x400085 <_start+5>     mov    edi, 0x1337            EDI => 0x1337\n"
        "   0x40008a <_start+10>    mov    esi, 0xdeadbeef        ESI => 0xdeadbeef\n"
        "   0x40008f <_start+15>    mov    ecx, 0x10              ECX => 0x10\n"
        "   0x400094 <_start+20>    syscall  <SYS_read>\n"
        "   0x400096 <_start+22>    mov    eax, 0xa               EAX => 0xa\n"
        " ► 0x40009b <_start+27>    int    0x80 <SYS_unlink>\n"
        "        name:      0x1337\n"
        "   0x40009d                add    byte ptr [rax], al\n"
        "   0x40009f                add    byte ptr [rax], al\n"
        "   0x4000a1                add    byte ptr [rax], al\n"
        "   0x4000a3                add    byte ptr [rax], al\n"
        "   0x4000a5                add    byte ptr [rax], al\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )


def test_context_disasm_syscalls_args_display_no_emulate(start_binary):
    gdb.execute("set emulate off")

    start_binary(SYSCALLS_BINARY)
    gdb.execute("nextsyscall")
    dis = gdb.execute("context disasm", to_string=True)
    assert dis == (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "─────────────────────[ DISASM / x86-64 / set emulate off ]──────────────────────\n"
        "   0x400080 <_start>       mov    eax, 0                 EAX => 0\n"
        "   0x400085 <_start+5>     mov    edi, 0x1337            EDI => 0x1337\n"
        "   0x40008a <_start+10>    mov    esi, 0xdeadbeef        ESI => 0xdeadbeef\n"
        "   0x40008f <_start+15>    mov    ecx, 0x10              ECX => 0x10\n"
        " ► 0x400094 <_start+20>    syscall  <SYS_read>\n"
        "        fd:        0x1337\n"
        "        buf:       0xdeadbeef\n"
        "        nbytes:    0\n"
        "   0x400096 <_start+22>    mov    eax, 0xa               EAX => 0xa\n"
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
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "─────────────────────[ DISASM / x86-64 / set emulate off ]──────────────────────\n"
        "   0x400085 <_start+5>     mov    edi, 0x1337            EDI => 0x1337\n"
        "   0x40008a <_start+10>    mov    esi, 0xdeadbeef        ESI => 0xdeadbeef\n"
        "   0x40008f <_start+15>    mov    ecx, 0x10              ECX => 0x10\n"
        "   0x400094 <_start+20>    syscall  <SYS_read>\n"
        "   0x400096 <_start+22>    mov    eax, 0xa               EAX => 0xa\n"
        " ► 0x40009b <_start+27>    int    0x80 <SYS_unlink>\n"
        "        name:      0x1337\n"
        "   0x40009d                add    byte ptr [rax], al\n"
        "   0x40009f                add    byte ptr [rax], al\n"
        "   0x4000a1                add    byte ptr [rax], al\n"
        "   0x4000a3                add    byte ptr [rax], al\n"
        "   0x4000a5                add    byte ptr [rax], al\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )


def test_context_backtrace_show_proper_symbol_names(start_binary):
    start_binary(MANGLING_BINARY)
    gdb.execute("break A::foo")
    gdb.execute("continue")

    backtrace = gdb.execute("context backtrace", to_string=True).split("\n")

    assert backtrace[0] == "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA"
    assert (
        backtrace[1]
        == "─────────────────────────────────[ BACKTRACE ]──────────────────────────────────"
    )

    assert re.match(r".*0   0x[0-9a-f]+ A::foo\(int, int\)", backtrace[2])

    # Match A::call_foo()+38 or similar: the offset may change so we match \d+ at the end
    assert re.match(r".*1   0x[0-9a-f]+ A::call_foo\(\)\+\d+", backtrace[3])

    # Match main+87 or similar offset
    assert re.match(r".*2   0x[0-9a-f]+ main\+\d+", backtrace[4])

    # Match __libc_start_main+243 or similar offset
    # Note: on Ubuntu 22.04 there will be __libc_start_call_main and then __libc_start_main
    # but on older distros there will be only __libc_start_main
    # Let's not bother too much about it and make it the last call assertion here
    assert re.match(
        r".*3   0x[0-9a-f]+ (__libc_start_main|__libc_start_call_main)\+\d+", backtrace[5]
    )

    assert (
        backtrace[-2]
        == "────────────────────────────────────────────────────────────────────────────────"
    )
    assert backtrace[-1] == ""


def test_context_disasm_works_properly_with_disasm_flavor_switch(start_binary):
    start_binary(SYSCALLS_BINARY)

    def assert_intel(out):
        assert "mov    eax, 0" in out[2]
        assert "mov    edi, 0x1337" in out[3]
        assert "mov    esi, 0xdeadbeef" in out[4]
        assert "mov    ecx, 0x10" in out[5]
        assert "syscall" in out[6]

    def assert_att(out):
        assert "mov    movl   $0, %eax" not in out[2]
        assert "mov    movl   $0x1337, %edi" not in out[3]
        assert "mov    movl   $0xdeadbeef, %esi" not in out[4]
        assert "mov    movl   $0x10, %ecx" not in out[5]
        assert "syscall" in out[6]

    out = gdb.execute("context disasm", to_string=True).split("\n")
    assert out[0] == "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA"
    assert (
        out[1] == "──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────"
    )
    assert_intel(out)

    gdb.execute("set disassembly-flavor att")
    assert out[0] == "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA"
    assert (
        out[1] == "──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────"
    )
    assert_att(out)


@pytest.mark.parametrize("patch_or_api", (True, False))
def test_context_disasm_proper_render_on_mem_change_issue_1818(start_binary, patch_or_api):
    start_binary(SYSCALLS_BINARY)

    old = gdb.execute("context disasm", to_string=True).split("\n")

    # Just a sanity check
    assert old[0] == "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA"
    assert "mov    eax, 0" in old[2]
    assert "mov    edi, 0x1337" in old[3]
    assert "mov    esi, 0xdeadbeef" in old[4]
    assert "mov    ecx, 0x10" in old[5]
    assert "syscall" in old[6]

    # 5 bytes because 'mov eax, 0' is 5 bytes long
    if patch_or_api:
        gdb.execute("patch $rip nop;nop;nop;nop;nop", to_string=True)
    else:
        # Do the same, but through write API
        pwndbg.aglib.memory.write(pwndbg.aglib.regs.rip, b"\x90" * 5)

    # Actual test: we expect the read memory to be different now ;)
    # (and not e.g. returned incorrectly from a not cleared cache)
    new = gdb.execute("context disasm", to_string=True).split("\n")

    assert new[0] == "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA"
    assert "nop" in new[2]
    assert "nop" in new[3]
    assert "nop" in new[4]
    assert "nop" in new[5]
    assert "nop" in new[6]
    assert "mov    edi, 0x1337" in new[7]
    assert "mov    esi, 0xdeadbeef" in new[8]
    assert "mov    ecx, 0x10" in new[9]
    assert "syscall" in new[10]


ONE_GADGET_BINARY = tests.binaries.get("onegadget.x86-64.out")


def test_context_disasm_fsbase_annotations(start_binary):
    """
    This test checks that fsbase support in annotations is working properly.

    If this breaks, either our x86 memory operand parser is broken, we cannot fetch fsbase, or we are not passing FSBASE to Unicorn.
    See: https://github.com/pwndbg/pwndbg/pull/2317

    For this test, we use a binary we know has a stack canary.
    Between compilations and between x86 vs x86_64, the exact instruction changes, but matches a regex pattern.

    """
    start_binary(ONE_GADGET_BINARY)

    gdb.execute("b break_here")
    gdb.execute("c")

    # In view, there should now be the fs/gs memory reference
    output = gdb.execute("context disasm", to_string=True).split("\n")

    pattern = re.compile(r"\b(mov|sub)\s+\w+,\s+(qword|dword)\s+ptr\s+(gs|fs):\[0x[0-9a-f]+\]")
    found = False
    for line in output:
        if pattern.search(line):
            found = True
            break

    assert found


LONG_FUNCTION_X64_BINARY = tests.binaries.get("long_function_x64.out")


def test_context_disasm_call_instruction_split(start_binary):
    """
    This checks for the following scenario:
    We are on a `call` instruction, and `si` to enter the function. Then, we do `fin` to return to the caller.
    There should be a split in the disassembly after the call instruction.
    """

    start_binary(LONG_FUNCTION_X64_BINARY)

    gdb.execute("start")
    # Call ctx so instructions get disassembled and cached
    gdb.execute("ctx")

    gdb.execute("si")
    gdb.execute("fin")

    dis = gdb.execute("context disasm", to_string=True)
    dis = pwndbg.color.strip(dis)

    expected = (
        "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA\n"
        "──────────────────────[ DISASM / x86-64 / set emulate on ]──────────────────────\n"
        "   0x400080 <_start>       call   function                    <function>\n"
        " \n"
        " ► 0x400085 <_start+5>     mov    eax, 2       EAX => 2\n"
        "   0x40008a <_start+10>    mov    ebx, 3       EBX => 3\n"
        "   0x40008f <_start+15>    add    rax, rbx     RAX => 5 (2 + 3)\n"
        "   0x400092 <_start+18>    xor    rax, rbx     RAX => 6 (5 ^ 3)\n"
        "   0x400095 <_start+21>    nop    \n"
        "   0x400096 <_start+22>    jmp    exit                        <exit>\n"
        "    ↓\n"
        "   0x4000ab <exit>         mov    eax, 0x3c              EAX => 0x3c\n"
        "   0x4000b0 <exit+5>       mov    edi, 0                 EDI => 0\n"
        "   0x4000b5 <exit+10>      syscall  <SYS_exit>\n"
        "   0x4000b7                add    byte ptr [rax], al\n"
        "────────────────────────────────────────────────────────────────────────────────\n"
    )

    assert dis == expected


def test_context_hide_sections(start_binary):
    start_binary(SYSCALLS_BINARY)

    # Disable one section
    out = gdb.execute("context", to_string=True)
    assert "REGISTERS" in out
    assert "STACK" in out
    gdb.execute("context regs --off")
    out = gdb.execute("context", to_string=True)
    assert "REGISTERS" not in out
    assert "STACK" in out
    gdb.execute("context regs --on")
    out = gdb.execute("context", to_string=True)
    assert "REGISTERS" in out
    assert "STACK" in out

    # Disable multiple sections
    gdb.execute("context stack disasm --off")
    out = gdb.execute("context", to_string=True)
    assert "STACK" not in out
    assert "DISASM" not in out
    gdb.execute("context stack --on")
    out = gdb.execute("context", to_string=True)
    assert "STACK" in out
    assert "DISASM" not in out
    gdb.execute("context stack disasm --on")
    out = gdb.execute("context", to_string=True)
    assert "STACK" in out
    assert "DISASM" in out

    # Disable all sections at once
    gdb.execute("context --off")
    out = gdb.execute("context", to_string=True)
    assert len(out) == 0
    gdb.execute("context --on")
    out = gdb.execute("context", to_string=True)
    assert "REGISTERS" in out
    assert "DISASM" in out


def test_context_history_prev_next(start_binary):
    start_binary(LONG_FUNCTION_X64_BINARY)

    # Add two context outputs to the history
    first_ctx = gdb.execute("ctx", to_string=True)
    gdb.execute("si")
    second_ctx = gdb.execute("ctx", to_string=True)
    assert first_ctx != second_ctx

    # Go back to the first context
    gdb.execute("contextprev")
    history_ctx = gdb.execute("ctx", to_string=True)
    assert first_ctx == history_ctx.replace(" (history 1/2)", "")
    assert "(history 1/2)" in history_ctx

    # Go to the second context again
    gdb.execute("contextnext")
    history_ctx = gdb.execute("ctx", to_string=True)
    assert second_ctx == history_ctx.replace(" (history 2/2)", "")
    assert "(history 2/2)" in history_ctx

    # Make sure new events are displayed right away
    # and disable the history scroll.
    gdb.execute("si")
    # Execute twice since the prompt hook isn't installed in tests
    # which causes the legend to still have the (history 2/2) string at first.
    gdb.execute("ctx", to_string=True)
    third_ctx = gdb.execute("ctx", to_string=True)
    assert history_ctx != third_ctx
    assert "(history " not in third_ctx

    # Check if cwatch expressions are also stored in the history
    gdb.execute("cwatch $rip")
    gdb.execute("cwatch execute 'p/z $rsp'")
    fourth_ctx = gdb.execute("ctx", to_string=True)
    assert "1: $rip = " in fourth_ctx
    assert "2: p/z $rsp\n$1 = 0x" in fourth_ctx

    # The next context shows a different output variable $2
    gdb.execute("si")
    fifth_ctx = gdb.execute("ctx", to_string=True)
    assert "1: $rip = " in fifth_ctx
    assert "2: p/z $rsp\n$2 = 0x" in fifth_ctx

    # Check that the expression section shows the old gdb variable $1 again.
    gdb.execute("contextprev")
    history_ctx = gdb.execute("ctx", to_string=True)
    assert "1: $rip = " in history_ctx
    assert "2: p/z $rsp\n$1 = 0x" in history_ctx

    gdb.execute("cunwatch 2")
    gdb.execute("cunwatch 1")


def test_context_history_search(start_binary):
    start_binary(REFERENCE_BINARY)

    gdb.execute("break main")
    gdb.execute("break break_here")

    gdb.execute("starti")
    gdb.execute("context")
    gdb.execute("continue")
    gdb.execute("context")
    gdb.execute("continue")
    gdb.execute("context")

    for _ in range(5):
        gdb.execute("ni")
        gdb.execute("context")

    # Search for something in the past
    search_result = gdb.execute("contextsearch puts@plt", to_string=True)
    assert "Found 1 match. Selected entry 2 for match in section 'disasm'." in search_result

    # Search for something that happened later and have the search wrap around
    search_result = gdb.execute("contextsearch 'Hello World'", to_string=True)
    assert "No more matches before the current entry. Starting from the top." in search_result
    assert "Found 7 matches. Selected entry 8 for match in section " in search_result
    search_result = gdb.execute("contextsearch 'Hello World'", to_string=True)
    assert "Found 7 matches. Selected entry 7 for match in section " in search_result

    # Select a section to search in
    search_result = gdb.execute("contextsearch 'Hello World' disasm", to_string=True)
    assert "Found 1 match. Selected entry 2 for match in section 'disasm'." in search_result

    # Search for something that doesn't exist
    search_result = gdb.execute("contextsearch 'nonexistent'", to_string=True)
    assert "String 'nonexistent' not found in context history." in search_result

    # Search in non-existing section
    search_result = gdb.execute("ctxsearch 'Hello World' nonexistent", to_string=True)
    assert "Section 'nonexistent' not found in context history." in search_result


def test_context_output_redirection(start_binary):
    start_binary(REFERENCE_BINARY)

    # Test CallOutput redirection
    def receive_output(output):
        receive_output.context_output = output

    receive_output.context_output = ""

    pwndbg.commands.context.contextoutput(
        "regs",
        receive_output,
        clearing=True,
        banner="top",
        width=80,
    )

    gdb.execute("start")

    out = gdb.execute("ctx", to_string=True)
    assert "REGISTERS" not in out
    assert "STACK" in out
    assert "REGISTERS" in receive_output.context_output
    assert "STACK" not in receive_output.context_output

    pwndbg.commands.context.resetcontextoutput("regs")
