from __future__ import annotations

import gdb

import tests

GOSAMPLE_X64 = tests.binaries.get("gosample.x64")
GOSAMPLE_X86 = tests.binaries.get("gosample.x86")


def test_typeinfo_go_x64():
    """
    Tests pwndbg's typeinfo knows about the Go x64 types.
    Catches: Python Exception <class 'gdb.error'> No type named u8.:
    Test catches the issue only if the binaries are not stripped.
    """
    gdb.execute("file " + GOSAMPLE_X64)
    start = gdb.execute("start", to_string=True)
    assert "Python Exception" not in start


def test_typeinfo_go_x86():
    """
    Tests pwndbg's typeinfo knows about the Go x32 types
    Catches: Python Exception <class 'gdb.error'> No type named u8.:
    Test catches the issue only if the binaries are not stripped.
    """
    gdb.execute("file " + GOSAMPLE_X86)
    start = gdb.execute("start", to_string=True)
    assert "Python Exception" not in start


def helper_test_dump(start_binary, filename):
    gdb.execute("set environment GOMAXPROCS=1")
    start_binary(filename)
    gdb.execute("break gosample.go:6", to_string=True)
    gdb.execute("continue")
    first = gdb.execute("go-dump any &x", to_string=True)
    assert first.strip() == """(map[string]int) &{"a": 1, "b": 2, "c": 3}"""
    gdb.execute("continue")
    second = gdb.execute("go-dump any &x", to_string=True)
    assert (
        second.strip()
        == """([]struct { a int; b string }) [struct {a: 1, b: "first"}, struct {a: 2, b: "second"}]"""
    )
    gdb.execute("continue")
    third = gdb.execute("go-dump -f 1 any &x", to_string=True)
    assert third.strip() == """([3]complex64) [(1.1 + 2.2i), (-2.5 - 5.0i), (4.2 - 2.1i)]"""


def test_go_dumping_x64(start_binary):
    helper_test_dump(start_binary, GOSAMPLE_X64)


def test_go_dumping_x86(start_binary):
    helper_test_dump(start_binary, GOSAMPLE_X86)
