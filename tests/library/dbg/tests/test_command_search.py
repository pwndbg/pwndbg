from __future__ import annotations

import re

from ....host import Controller
from . import get_binary
from . import launch_to
from . import pwndbg_test

SEARCH_BINARY = get_binary("search_memory.out")
SEARCH_PATTERN = 0xD00DBEEF
SEARCH_PATTERN2 = 0xABCDEF1234567890


@pwndbg_test
async def test_command_search_literal(ctrl: Controller) -> None:
    """
    Searches for a string literal in a few different ways
    """
    await launch_to(ctrl, SEARCH_BINARY, "break_here")

    # Perform three equivalent searches, and chop off the first line of verbosity.
    result0 = (await ctrl.execute_and_capture("search -t bytes Hello!")).splitlines()[1:]
    result1 = (await ctrl.execute_and_capture("search -t bytes -x 48656c6c6f21")).splitlines()[1:]
    result2 = (await ctrl.execute_and_capture("search -t string Hello!")).splitlines()[1:]

    assert result0 == result1
    assert result1 == result2

    for line in result0:
        assert re.match(".* .* 0x216f6c6c6548 /\\* 'Hello!' \\*/", line) is not None


@pwndbg_test
async def test_command_search_limit_single_page(ctrl: Cotnroller) -> None:
    """
    Tests simple search limit for single memory page
    """
    await launch_to(ctrl, SEARCH_BINARY, "break_here")

    search_limit = 10
    result_str = await ctrl.execute_and_capture(
        f"search --dword {SEARCH_PATTERN} -l {search_limit} -w",
    )
    result_count = 0
    result_value = None
    for line in result_str.split("\n"):
        if line.startswith("[anon_"):
            if not result_value:
                result_value = line.split(" ")[2]
            result_count += 1

    assert result_count == search_limit
    assert result_value == hex(SEARCH_PATTERN)


@pwndbg_test
async def test_command_search_limit_multiple_pages(ctrl: Controller) -> None:
    """
    Tests simple search limit for multiple memory pages
    """
    await launch_to(ctrl, SEARCH_BINARY, "break_here")

    def filter_results(line):
        return hex(SEARCH_PATTERN2).lower() in line.lower()

    total_entries = 3
    result_str: str = await ctrl.execute_and_capture(f"search -8 {SEARCH_PATTERN2}")
    result_count = len(list(filter(filter_results, result_str.splitlines())))
    assert result_count == total_entries

    search_limit = 2
    result_str = await ctrl.execute_and_capture(f"search -8 {SEARCH_PATTERN2} -l {search_limit}")
    result_count = len(list(filter(filter_results, result_str.splitlines())))
    assert result_count == search_limit


@pwndbg_test
async def test_command_search_alignment(ctrl: Controller) -> None:
    """
    Tests aligned search
    """
    await launch_to(ctrl, SEARCH_BINARY, "break_here")

    alignment = 8
    result_str = await ctrl.execute_and_capture(
        f"search --dword {SEARCH_PATTERN} -a {alignment} -w"
    )
    for line in result_str.split("\n"):
        if line.startswith("[anon_"):
            result_address = line.split(" ")[1]
            assert int(result_address, 16) % alignment == 0


@pwndbg_test
async def test_command_search_step(ctrl: Controller) -> None:
    """
    Tests stepped search
    """
    await launch_to(ctrl, SEARCH_BINARY, "break_here")

    step = 0x1000
    result_str = await ctrl.execute_and_capture(f"search --dword {SEARCH_PATTERN} -s {step} -w")
    result_count = 0
    for line in result_str.split("\n"):
        if line.startswith("[anon_"):
            result_count += 1

    # We allocate 0x100000 bytes
    assert result_count == 0x100


@pwndbg_test
async def test_command_search_byte_width(ctrl: Controller) -> None:
    """
    Tests 1-byte search
    """
    await launch_to(ctrl, SEARCH_BINARY, "break_here")

    result_str = await ctrl.execute_and_capture("search --byte 0xef -w")
    result_count = 0
    for line in result_str.split("\n"):
        if line.startswith("[anon_"):
            result_count += 1

    assert result_count > 0x100


@pwndbg_test
async def test_command_search_word_width(ctrl: Controller) -> None:
    """
    Tests 2-byte word search
    """
    await launch_to(ctrl, SEARCH_BINARY, "break_here")

    result_str = await ctrl.execute_and_capture("search --word 0xbeef -w")
    result_count = 0
    for line in result_str.split("\n"):
        if line.startswith("[anon_"):
            result_count += 1

    assert result_count > 0x100


@pwndbg_test
async def test_command_search_dword_width(ctrl: Controller) -> None:
    """
    Tests 4-byte dword search
    """
    await launch_to(ctrl, SEARCH_BINARY, "break_here")

    result_str = await ctrl.execute_and_capture("search --dword 0xd00dbeef -w")
    result_count = 0
    for line in result_str.split("\n"):
        if line.startswith("[anon_"):
            result_count += 1

    assert result_count > 0x100


@pwndbg_test
async def test_command_search_qword_width(ctrl: Controller) -> None:
    """
    Tests 8-byte qword search
    """
    await launch_to(ctrl, SEARCH_BINARY, "break_here")

    result_str = await ctrl.execute_and_capture("search --dword 0x00000000d00dbeef -w")
    result_count = 0
    for line in result_str.split("\n"):
        if line.startswith("[anon_"):
            result_count += 1

    assert result_count > 0x100


@pwndbg_test
async def test_command_search_rwx(ctrl: Controller) -> None:
    """
    Tests searching for rwx memory only
    """
    await launch_to(ctrl, SEARCH_BINARY, "break_here")

    result_str = await ctrl.execute_and_capture("search --dword 0x00000000d00dbeef -w -x")
    result_count = 0
    for line in result_str.split("\n"):
        if line.startswith("[anon_"):
            result_count += 1

    assert result_count == 0


@pwndbg_test
async def test_command_search_asm(ctrl: Controller) -> None:
    """
    Tests searching for asm instructions
    """
    await launch_to(ctrl, SEARCH_BINARY, "break_here")

    result_str = await ctrl.execute_and_capture('search --asm "add rax, rdx" search_memory')
    result_count = 0
    for line in result_str.split("\n"):
        if line.startswith("search_memory"):
            result_count += 1
    assert result_count == 2


@pwndbg_test
async def test_command_set_breakpoint_search_asm(ctrl: Controller) -> None:
    """
    Tests setting breakpoints on found asm instructions
    """
    await launch_to(ctrl, SEARCH_BINARY, "break_here")

    result_str = await ctrl.execute_and_capture('search --asmbp "add rax, rdx" search_memory')
    result_count = 0
    for line in result_str.split("\n"):
        if line.startswith("Breakpoint"):
            result_count += 1
    assert result_count == 2
