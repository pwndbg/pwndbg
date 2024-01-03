from __future__ import annotations

import gdb

import tests

SEARCH_BINARY = tests.binaries.get("search_memory.out")
SEARCH_PATTERN = 0xD00DBEEF


def test_command_search_limit(start_binary):
    """
    Tests simple search limit
    """
    start_binary(SEARCH_BINARY)

    gdb.execute("break break_here")
    gdb.execute("run")

    search_limit = 10
    result_str = gdb.execute(
        f"search --dword {SEARCH_PATTERN} -l {search_limit} -w", to_string=True
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


def test_command_search_alignment(start_binary):
    """
    Tests aligned search
    """
    start_binary(SEARCH_BINARY)

    gdb.execute("break break_here")
    gdb.execute("run")

    alignment = 8
    result_str = gdb.execute(f"search --dword {SEARCH_PATTERN} -a {alignment} -w", to_string=True)
    for line in result_str.split("\n"):
        if line.startswith("[anon_"):
            result_address = line.split(" ")[1]
            assert int(result_address, 16) % alignment == 0


def test_command_search_step(start_binary):
    """
    Tests stepped search
    """
    start_binary(SEARCH_BINARY)

    gdb.execute("break break_here")
    gdb.execute("run")

    step = 0x1000
    result_str = gdb.execute(f"search --dword {SEARCH_PATTERN} -s {step} -w", to_string=True)
    result_count = 0
    for line in result_str.split("\n"):
        if line.startswith("[anon_"):
            result_count += 1

    # We allocate 0x100000 bytes
    assert result_count == 0x100


def test_command_search_byte_width(start_binary):
    """
    Tests 1-byte search
    """
    start_binary(SEARCH_BINARY)

    gdb.execute("break break_here")
    gdb.execute("run")

    result_str = gdb.execute("search --byte 0xef -w", to_string=True)
    result_count = 0
    for line in result_str.split("\n"):
        if line.startswith("[anon_"):
            result_count += 1

    assert result_count > 0x100


def test_command_search_word_width(start_binary):
    """
    Tests 2-byte word search
    """
    start_binary(SEARCH_BINARY)

    gdb.execute("break break_here")
    gdb.execute("run")

    result_str = gdb.execute("search --word 0xbeef -w", to_string=True)
    result_count = 0
    for line in result_str.split("\n"):
        if line.startswith("[anon_"):
            result_count += 1

    assert result_count > 0x100


def test_command_search_dword_width(start_binary):
    """
    Tests 4-byte dword search
    """
    start_binary(SEARCH_BINARY)

    gdb.execute("break break_here")
    gdb.execute("run")

    result_str = gdb.execute("search --dword 0xd00dbeef -w", to_string=True)
    result_count = 0
    for line in result_str.split("\n"):
        if line.startswith("[anon_"):
            result_count += 1

    assert result_count > 0x100


def test_command_search_qword_width(start_binary):
    """
    Tests 8-byte qword search
    """
    start_binary(SEARCH_BINARY)

    gdb.execute("break break_here")
    gdb.execute("run")

    result_str = gdb.execute("search --dword 0x00000000d00dbeef -w", to_string=True)
    result_count = 0
    for line in result_str.split("\n"):
        if line.startswith("[anon_"):
            result_count += 1

    assert result_count > 0x100


def test_command_search_rwx(start_binary):
    """
    Tests searching for rwx memory only
    """
    start_binary(SEARCH_BINARY)

    gdb.execute("break break_here")
    gdb.execute("run")

    result_str = gdb.execute("search --dword 0x00000000d00dbeef -w -x", to_string=True)
    result_count = 0
    for line in result_str.split("\n"):
        if line.startswith("[anon_"):
            result_count += 1

    assert result_count == 0
