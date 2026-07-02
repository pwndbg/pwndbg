from __future__ import annotations

import re

import pytest

from ....host import Controller
from . import break_at_sym
from . import get_binary
from . import launch_to
from . import pwndbg_test

REFERENCE_BINARY = get_binary("reference-binary.native.out")
USE_FDS_BINARY = get_binary("use-fds.native.out")
TABSTOP_BINARY = get_binary("tabstop.native.out")
SYSCALLS_BINARY = get_binary("syscalls.x86-64.out")
MANGLING_BINARY = get_binary("symbol_1600_and_752.native.out")
STACK_VARS_BINARY = get_binary("stack_vars.native.out")
CONTEXT_ARGS_BINARY = get_binary("context_args.native.out")


@pwndbg_test
async def test_context_disasm_show_fd_filepath(ctrl: Controller) -> None:
    """
    Tests context disasm command and whether it shows properly opened fd filepath
    """
    import pwndbg.aglib
    import pwndbg.aglib.memory
    import pwndbg.commands
    import pwndbg.commands.canary
    import pwndbg.commands.context

    await launch_to(ctrl, USE_FDS_BINARY, "main")

    # Stop on read(0, ...) -> should show /dev/pts/X or pipe:X on CI
    await ctrl.execute("nextcall")

    out = pwndbg.commands.context.context_disasm()
    assert "[ DISASM " in out[0]  # Sanity check

    call_read_line_idx = out.index(
        next(line for line in out if "<read@plt>" in line or "<read>" in line)
    )
    lines_after_call_read = out[call_read_line_idx:]

    line_call_read, line_fd, line_buf, line_nbytes, *_rest = lines_after_call_read

    assert "read" in line_call_read

    # When running tests with GNU Parallel, sometimes the file name looks
    # '/tmp/parZ4YC4.par', and occasionally '(deleted)' is present after the
    # filename
    line_fd = line_fd.strip()
    assert re.match(
        r"fd:\s+1 \((/dev/pts/\d+|/tmp/par.+\.par(?: \(deleted\))?|pipe:\[\d+\])\)", line_fd
    )

    line_buf = line_buf.strip()
    assert re.match(r"buf:\s+0x[0-9a-f]+(?: \{buf\})? ◂— 0", line_buf)

    line_nbytes = line_nbytes.strip()
    assert re.match(r"nbytes:\s+0", line_nbytes)

    # Stop on open(...)
    await ctrl.execute("nextcall")
    # Stop on read(...) -> should show use-fds.out
    await ctrl.execute("nextcall")

    out = pwndbg.commands.context.context_disasm()
    assert "[ DISASM " in out[0]  # Sanity check

    call_read_line_idx = out.index(
        next(line for line in out if "<read@plt>" in line or "<read>" in line)
    )
    lines_after_call_read = out[call_read_line_idx:]

    line_call_read, line_fd, line_buf, line_nbytes, *_rest = lines_after_call_read

    line_fd = line_fd.strip()
    assert re.match(r"fd:\s+3\s+\(.*?/tests/binaries/host/use-fds.native.out\)", line_fd)

    line_buf = line_buf.strip()
    assert re.match(r"buf:\s+0x[0-9a-f]+(?: \{buf\})? ◂— 0", line_buf)

    line_nbytes = line_nbytes.strip()
    assert re.match(r"nbytes:\s+0x10", line_nbytes)


@pytest.mark.parametrize("sections", ("''", '""', "none", "-"))
@pwndbg_test
async def test_empty_context_sections(ctrl: Controller, sections: str) -> None:
    import pwndbg

    await ctrl.launch(USE_FDS_BINARY)

    # Sanity checkdefault_ctx_sects
    default_ctx_sects = (
        "regs disasm code ghidra stack backtrace expressions threads heap_tracker last_signal"
    )
    assert pwndbg.config.context_sections.value == default_ctx_sects
    assert (await ctrl.execute_and_capture("context")) != ""

    # Actual test check
    await ctrl.execute(f"set context-sections {sections}")
    assert pwndbg.config.context_sections.value == ""
    assert (await ctrl.execute_and_capture("context")) == ""

    # Bring back old values && sanity check
    await ctrl.execute(f"set context-sections '{default_ctx_sects}'")
    assert pwndbg.config.context_sections.value == default_ctx_sects
    assert (await ctrl.execute_and_capture("context")) != ""


@pwndbg_test
async def test_source_code_tabstop(ctrl: Controller) -> None:
    await ctrl.launch(TABSTOP_BINARY)

    # Run until line 6
    await ctrl.execute("b tabstop.native.c:6")
    await ctrl.cont()

    # Default context-code-tabstop = 8
    src = await ctrl.execute_and_capture("context code")
    if "LEGEND" in src and "─[" not in src:
        pytest.skip("Source code not available in this environment")

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
    await ctrl.execute("set context-code-tabstop 2")
    src = await ctrl.execute_and_capture("context code")
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
    await ctrl.execute("set context-code-tabstop 0")
    src = await ctrl.execute_and_capture("context code")
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


@pwndbg_test
async def test_context_disasm_syscalls_args_display(ctrl: Controller) -> None:
    await ctrl.launch(SYSCALLS_BINARY)

    await ctrl.execute("nextsyscall")
    dis = await ctrl.execute_and_capture("context disasm")
    # The regex matches: syscall (x86-64), svc (aarch64), or int 0x80 (x86)
    assert re.search(r"(syscall|svc|int\s+0x80)", dis), (
        f"Syscall instruction not found in disassembly:\n{dis}"
    )
    assert "fd:" in dis, f"'fd:' argument not found in disassembly:\n{dis}"
    assert "buf:" in dis, f"'buf:' argument not found in disassembly:\n{dis}"
    assert "nbytes:" in dis, f"'nbytes:' argument not found in disassembly:\n{dis}"

    await ctrl.execute("nextsyscall")
    dis = await ctrl.execute_and_capture("context disasm")
    assert re.search(r"(syscall|svc|int\s+0x80)", dis), (
        f"Second syscall instruction not found in disassembly:\n{dis}"
    )
    # Some architectures call it 'name', others 'path' or 'filename'
    assert any(x in dis for x in ("name:", "path:", "filename:")), (
        f"Syscall path argument not found in disassembly:\n{dis}"
    )


@pwndbg_test
async def test_context_disasm_syscalls_args_display_no_emulate(ctrl: Controller) -> None:
    await ctrl.execute("set emulate off")

    await ctrl.launch(SYSCALLS_BINARY)

    await ctrl.execute("nextsyscall")
    dis = await ctrl.execute_and_capture("context disasm")

    assert re.search(r"(syscall|svc|int\s+0x80)", dis), (
        f"Syscall instruction not found (no emulate):\n{dis}"
    )
    assert "fd:" in dis, f"'fd:' argument not found (no emulate):\n{dis}"
    assert "buf:" in dis, f"'buf:' argument not found (no emulate):\n{dis}"
    assert "nbytes:" in dis, f"'nbytes:' argument not found (no emulate):\n{dis}"

    await ctrl.execute("nextsyscall")
    dis = await ctrl.execute_and_capture("context disasm")
    assert re.search(r"(syscall|svc|int\s+0x80)", dis), (
        f"Second syscall instruction not found (no emulate):\n{dis}"
    )
    assert any(x in dis for x in ("name:", "path:", "filename:")), (
        f"Syscall path argument not found (no emulate):\n{dis}"
    )


@pwndbg_test
async def test_context_backtrace_show_proper_symbol_names(ctrl: Controller) -> None:
    await ctrl.launch(MANGLING_BINARY)

    await ctrl.execute("b A::foo")
    await ctrl.cont()

    backtrace = (await ctrl.execute_and_capture("context backtrace")).split("\n")

    assert backtrace[0] == "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA"
    assert (
        backtrace[1]
        == "─────────────────────────────────[ BACKTRACE ]──────────────────────────────────"
    )

    assert re.match(r".*0\s+0x[0-9a-f]+\s+A::foo\(int, int\)(\+\d+)?", backtrace[2])

    # Match A::call_foo()+38 or similar: the offset may change so we match \d+ at the end
    assert re.match(r".*1\s+0x[0-9a-f]+\s+A::call_foo\(\)\+\d+", backtrace[3])

    # Match main+87 or similar offset
    assert re.match(r".*2\s+0x[0-9a-f]+\s+main\+\d+", backtrace[4])

    # Match __libc_start_main+243 or similar offset
    # Note: on Ubuntu 22.04 there will be __libc_start_call_main and then __libc_start_main
    # but on older distros there will be only __libc_start_main
    # Let's not bother too much about it and make it the last call assertion here
    assert re.match(
        r".*3\s+0x[0-9a-f]+\s+(__libc_start_main|__libc_start_call_main)\+\d+", backtrace[5]
    )

    assert (
        backtrace[-2]
        == "────────────────────────────────────────────────────────────────────────────────"
    )
    assert backtrace[-1] == ""


@pwndbg_test
async def test_context_disasm_works_properly_with_disasm_flavor_switch(ctrl: Controller) -> None:
    await ctrl.launch(SYSCALLS_BINARY)

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

    out = (await ctrl.execute_and_capture("context disasm")).split("\n")
    assert out[0] == "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA"
    assert any("DISASM" in line and "set emulate on" in line for line in out[1:2])
    assert_intel(out)

    await ctrl.execute("set disassembly-flavor att")
    out = (await ctrl.execute_and_capture("context disasm")).split("\n")
    assert out[0] == "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA"
    assert any("DISASM" in line and "set emulate on" in line for line in out[1:2])
    assert_att(out)


@pytest.mark.parametrize("patch_or_api", (True, False))
@pwndbg_test
async def test_context_disasm_proper_render_on_mem_change_issue_1818(
    ctrl: Controller, patch_or_api: bool
) -> None:
    import pwndbg.aglib.memory

    await ctrl.launch(SYSCALLS_BINARY)

    old = (await ctrl.execute_and_capture("context disasm")).split("\n")

    # Just a sanity check
    assert old[0] == "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA"
    if pwndbg.aglib.arch.name == "x86-64":
        assert "mov    eax, 0" in old[2]
        assert "mov    edi, 0x1337" in old[3]
        assert "mov    esi, 0xdeadbeef" in old[4]
        assert "mov    ecx, 0x10" in old[5]
        assert "syscall" in old[6]

    # Overwrite
    pc = pwndbg.aglib.regs.pc
    assert pc is not None

    # On x86, we patch 5 bytes (size of 'mov edi, 0x1337')
    # On other architectures, we patch at least one instruction size
    patch_size = 5 if pwndbg.aglib.arch.name == "x86-64" else pwndbg.aglib.arch.ptrsize

    if patch_or_api:
        await ctrl.execute(f"patch {pc + patch_size} nop;nop;nop;nop;nop")
    else:
        # Do the same, but through write API
        pwndbg.aglib.memory.write(pc + patch_size, b"\x90" * 5)

    # Actual test: we expect the read memory to be different now ;)
    # (and not e.g. returned incorrectly from a not cleared cache)
    new = (await ctrl.execute_and_capture("context disasm")).split("\n")

    assert new[0] == "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA"
    # The exact line index might shift, so we check for presence of nops
    assert any("nop" in line for line in new)


ONE_GADGET_BINARY = get_binary("onegadget.x86-64.out")


@pwndbg_test
async def test_context_disasm_fsbase_annotations(ctrl: Controller) -> None:
    """
    This test checks that fsbase support in annotations is working properly.

    If this breaks, either our x86 memory operand parser is broken, we cannot fetch fsbase, or we are not passing FSBASE to Unicorn.
    See: https://github.com/pwndbg/pwndbg/pull/2317

    For this test, we use a binary we know has a stack canary.
    """
    import pwndbg
    if pwndbg.aglib.arch.name != "x86-64":
        pytest.skip("Test uses x86-64 specific binary")

    await launch_to(ctrl, ONE_GADGET_BINARY, "break_here")

    # In view, there should now be the fs/gs memory reference
    output = (await ctrl.execute_and_capture("context disasm")).split("\n")

    pattern = re.compile(r"\b(mov|sub)\s+\w+,\s+(qword|dword)\s+ptr\s+(gs|fs):\[.*0x[0-9a-f]+.*\]")
    found = False
    for line in output:
        if pattern.search(line):
            found = True
            break

    assert found


LONG_FUNCTION_X64_BINARY = get_binary("long_function.x86-64.out")


@pwndbg_test
async def test_context_disasm_call_instruction_split(ctrl: Controller) -> None:
    """
    This checks for the following scenario:
    We are on a `call` instruction, and `si` to enter the function. Then, we do `fin` to return to the caller.
    There should be a split in the disassembly after the call instruction.
    """
    import pwndbg.aglib

    import pwndbg.color

    if pwndbg.aglib.arch.name != "x86-64":
        pytest.skip("Test uses x86-64 specific binary")

    await ctrl.launch(LONG_FUNCTION_X64_BINARY)

    # Call ctx so instructions get disassembled and cached
    await ctrl.execute("ctx")

    await ctrl.step_instruction()
    await ctrl.execute("fin")

    dis = await ctrl.execute_and_capture("context disasm")
    dis_lines = pwndbg.color.strip(dis).split("\n")

    assert "LEGEND: STACK | HEAP | CODE | DATA | WX | RODATA" in dis_lines[0]
    # Check that we have a call instruction and then a split (empty line or arrow)
    found_call = False
    found_split = False
    for line in dis_lines:
        if "call   function" in line:
            found_call = True
        if found_call and not line.strip():
            found_split = True
            break

    assert found_call, "Call instruction not found in disassembly"
    assert found_split, "Disassembly split after call instruction not found"
    assert "► 0x400085 <_start+5>     mov    eax, 2" in dis


@pwndbg_test
async def test_context_hide_sections(ctrl: Controller) -> None:
    await ctrl.launch(SYSCALLS_BINARY)

    # Disable one section
    out = await ctrl.execute_and_capture("context")
    assert "REGISTERS" in out
    assert "STACK" in out
    await ctrl.execute("context regs --off")
    out = await ctrl.execute_and_capture("context")
    assert "REGISTERS" not in out
    assert "STACK" in out
    await ctrl.execute("context regs --on")
    out = await ctrl.execute_and_capture("context")
    assert "REGISTERS" in out
    assert "STACK" in out

    # Disable multiple sections
    await ctrl.execute("context stack disasm --off")
    out = await ctrl.execute_and_capture("context")
    assert "STACK" not in out
    assert "DISASM" not in out
    await ctrl.execute("context stack --on")
    out = await ctrl.execute_and_capture("context")
    assert "STACK" in out
    assert "DISASM" not in out
    await ctrl.execute("context stack disasm --on")
    out = await ctrl.execute_and_capture("context")
    assert "STACK" in out
    assert "DISASM" in out

    # Disable all sections at once
    await ctrl.execute("context --off")
    out = await ctrl.execute_and_capture("context")
    assert len(out) == 0
    await ctrl.execute("context --on")
    out = await ctrl.execute_and_capture("context")
    assert "REGISTERS" in out
    assert "DISASM" in out


def extract_context_sections(output: str) -> list[str]:
    # Strip ANSI color codes
    clean_output = re.sub(r"\x1b\[[0-9;]*m", "", output)

    # Match section headers: ─[ SECTION_NAME ... ]─
    # Capture everything inside the brackets
    section_pattern = re.compile(r"─\[\s*([^\]]+?)\s*\]─")

    matches = section_pattern.findall(clean_output)

    section_names = []
    for m in matches:
        # Split by " / " to separate section name from config info
        # e.g., "REGISTERS / show-flags off / show-compact-regs off" -> "REGISTERS"
        parts = m.split(" / ")
        section_name = parts[0].strip()
        section_names.append(section_name)

    return section_names


@pwndbg_test
async def test_context_all_sections_flag(ctrl: Controller) -> None:
    """
    Tests that context -a/--all shows all sections regardless of context-sections config
    """
    await launch_to(ctrl, CONTEXT_ARGS_BINARY, "main")

    # First, set context-sections to only regs
    await ctrl.execute("set context-sections regs")
    default_out = await ctrl.execute_and_capture("context")
    default_sections = extract_context_sections(default_out)
    assert default_sections == ["REGISTERS"]

    # Now use -a flag. It should capture all sections regardless of config
    all_out = await ctrl.execute_and_capture("context -a")
    core_sections = {"REGISTERS", "DISASM", "STACK", "BACKTRACE"}
    all_sections = set(extract_context_sections(all_out))

    # Core sections must be present. Others (like SOURCE, LAST SIGNAL) are optional.
    assert core_sections.issubset(all_sections)

    # Now proceed to next function call (i.e at func_with_args) for testing ARGUMENTS section
    await ctrl.execute("nextcall")

    # Now use -a flag - should include ARGUMENTS section when displaying all sections
    all_out_after_nextcall = await ctrl.execute_and_capture("ctx -a")
    core_sections.add("ARGUMENTS")

    all_sections_after_nextcall = set(extract_context_sections(all_out_after_nextcall))
    assert core_sections.issubset(all_sections_after_nextcall)

    # Verify --all alias works identically
    alias_out = await ctrl.execute_and_capture("ctx --all")
    assert alias_out == all_out_after_nextcall


@pwndbg_test
async def test_context_history_prev_next(ctrl: Controller) -> None:
    import pwndbg

    await ctrl.launch(LONG_FUNCTION_X64_BINARY)

    # Add two context outputs to the history
    first_ctx = await ctrl.execute_and_capture("ctx")
    await ctrl.step_instruction()
    second_ctx = await ctrl.execute_and_capture("ctx")
    assert first_ctx != second_ctx

    # Go back to the first context
    await ctrl.execute("contextprev")
    history_ctx = await ctrl.execute_and_capture("ctx")
    assert first_ctx == history_ctx.replace(" (history 1/2)", "")
    assert "(history 1/2)" in history_ctx

    # Go to the second context again
    await ctrl.execute("contextnext")
    history_ctx = await ctrl.execute_and_capture("ctx")
    assert second_ctx == history_ctx.replace(" (history 2/2)", "")
    assert "(history 2/2)" in history_ctx

    # Make sure new events are displayed right away
    # and disable the history scroll.
    await ctrl.step_instruction()
    # Execute twice since the prompt hook isn't installed in tests
    # which causes the legend to still have the (history 2/2) string at first.
    await ctrl.execute("ctx")
    third_ctx = await ctrl.execute_and_capture("ctx")
    assert history_ctx != third_ctx
    assert "(history " not in third_ctx

    if pwndbg.dbg.is_gdblib_available():
        # Currently only works in GDB.
        import gdb

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


@pwndbg_test
async def test_context_history_search(ctrl: Controller) -> None:

    await ctrl.launch(REFERENCE_BINARY)

    await ctrl.execute("context")

    break_at_sym("main")
    break_at_sym("break_here")

    await ctrl.cont()
    await ctrl.execute("context")
    await ctrl.cont()
    await ctrl.execute("context")

    for _ in range(5):
        await ctrl.execute("ni")
        await ctrl.execute("context")

    # Search for something in the past
    search_result0 = await ctrl.execute_and_capture("contextsearch puts@plt")
    search_result1 = await ctrl.execute_and_capture("contextsearch puts disasm")

    assert (
        "Found 1 match. Selected entry 2 for match in section 'disasm'." in search_result0
        or "Found 1 match. Selected entry 2 for match in section 'disasm'." in search_result1
    )

    # Search for something that happened later and have the search wrap around
    search_result = await ctrl.execute_and_capture("contextsearch 'Hello World'")
    assert "No more matches before the current entry. Starting from the top." in search_result
    assert "Found 7 matches. Selected entry 8 for match in section " in search_result
    search_result = await ctrl.execute_and_capture("contextsearch 'Hello World'")
    assert "Found 7 matches. Selected entry 7 for match in section " in search_result

    # Select a section to search in
    search_result = await ctrl.execute_and_capture("contextsearch 'Hello World' disasm")
    assert "Found 1 match. Selected entry 2 for match in section 'disasm'." in search_result

    # Search for something that doesn't exist
    search_result = await ctrl.execute_and_capture("contextsearch 'nonexistent'")
    assert "String 'nonexistent' not found in context history." in search_result

    # Search in non-existing section
    search_result = await ctrl.execute_and_capture("ctxsearch 'Hello World' nonexistent")
    assert "Section 'nonexistent' not found in context history." in search_result


@pwndbg_test
async def test_context_output_redirection(ctrl: Controller) -> None:
    import pwndbg.commands.context

    await ctrl.launch(REFERENCE_BINARY)

    # Test CallOutput redirection
    def receive_output(output):
        receive_output.context_output = output  # type: ignore[attr-defined]

    receive_output.context_output = ""  # type: ignore[attr-defined]

    pwndbg.commands.context.contextoutput(
        "regs",
        receive_output,
        clearing=True,
        banner="top",
        width=80,
    )

    out = await ctrl.execute_and_capture("ctx")
    assert "REGISTERS" not in out
    assert "STACK" in out
    assert "REGISTERS" in receive_output.context_output  # type: ignore[attr-defined]
    assert "STACK" not in receive_output.context_output  # type: ignore[attr-defined]

    pwndbg.commands.context.resetcontextoutput("regs")


@pwndbg_test
async def test_stack_variable_names_from_dwarf(ctrl: Controller) -> None:
    """
    Test that stack variable names from DWARF debug info are displayed correctly
    """
    import pwndbg.aglib.stack
    import pwndbg.commands.context
    import pwndbg.dbg_mod

    # Launch directly to inner_function where the variables are
    await launch_to(ctrl, STACK_VARS_BINARY, "inner_function")

    # Test direct API: pwndbg.aglib.stack.get_stack_var_name()
    # Get addresses of local variables
    frame = pwndbg.dbg.selected_frame()
    assert frame is not None
    buffer_addr = int(frame.evaluate_expression("&buffer"))
    local_var_addr = int(frame.evaluate_expression("&local_var"))

    # Test that get_stack_var_name returns correct names
    assert pwndbg.aglib.stack.get_stack_var_name(buffer_addr) == "buffer"
    assert pwndbg.aglib.stack.get_stack_var_name(local_var_addr) == "local_var"

    # Test offset notation for addresses within variables
    # buffer is 64 bytes, so buffer+0x10 should show "buffer+0x10"
    buffer_offset_addr = buffer_addr + 0x10
    offset_result = pwndbg.aglib.stack.get_stack_var_name(buffer_offset_addr)
    assert offset_result == "buffer+0x10"

    # Test that telescope shows variable names
    telescope_out = await ctrl.execute_and_capture(f"telescope {buffer_addr:#x} 1")
    assert "{buffer}" in telescope_out


@pwndbg_test
async def test_regs_command_resolves_sp_pc_aliases(ctrl: Controller) -> None:
    """
    If running `regs pc` or `regs sp`, these aliases should be resolved
    to the real architectural names of the registers.
    """
    import pwndbg.aglib

    await ctrl.launch(REFERENCE_BINARY)

    sp_name = pwndbg.aglib.regs.current.stack
    pc_name = pwndbg.aglib.regs.current.pc

    real_sp_value = pwndbg.aglib.regs.read_reg(sp_name)
    real_pc_value = pwndbg.aglib.regs.read_reg(pc_name)

    regs_sp_output = await ctrl.execute_and_capture("regs sp")
    regs_pc_output = await ctrl.execute_and_capture("regs pc")

    assert sp_name.upper() in regs_sp_output
    assert real_sp_value is not None
    assert hex(real_sp_value) in regs_sp_output

    assert pc_name.upper() in regs_pc_output
    assert real_pc_value is not None
    assert hex(real_pc_value) in regs_pc_output


@pwndbg_test
async def test_cli_fixup_resolves_sp_pc_aliases(ctrl: Controller) -> None:
    """
    CLI argument fixup should resolve "sp" and "pc" correctly.

    Note:
    The fixup process by default (without any special handling of these aliases)
    would just adds a "$" infront of register names.
    GDB reading $sp and $pc will internally handle the conversion, meaning this test
    passes without any special logic in the register fixup.

    However, this is not necessarily true of all underlying debuggers.
    """
    import pwndbg.aglib

    await ctrl.launch(REFERENCE_BINARY)

    sp_name = pwndbg.aglib.regs.current.stack
    pc_name = pwndbg.aglib.regs.current.pc

    real_sp_value = pwndbg.aglib.regs.read_reg(sp_name)
    real_pc_value = pwndbg.aglib.regs.read_reg(pc_name)

    regs_sp_output = await ctrl.execute_and_capture("telescope sp 1")
    regs_pc_output = await ctrl.execute_and_capture("telescope pc 1")

    assert sp_name in regs_sp_output
    assert real_sp_value is not None
    assert hex(real_sp_value) in regs_sp_output

    assert pc_name in regs_pc_output
    assert real_pc_value is not None
    assert hex(real_pc_value) in regs_pc_output
