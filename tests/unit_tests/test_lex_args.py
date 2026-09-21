from __future__ import annotations

import pytest

from pwndbg.lib.strings import lex_args


@pytest.mark.parametrize(
    ("command_line", "expected"),
    (
        # Ordinary command lines.
        ("", []),
        ("   ", []),
        ("nearpc", ["nearpc"]),
        ("nearpc -f 10", ["nearpc", "-f", "10"]),
        ("telescope $rsp+8", ["telescope", "$rsp+8"]),
        # Quoting and escaping, same as `shlex.split`.
        ('search -s "a b"', ["search", "-s", "a b"]),
        ("search -s 'a b'", ["search", "-s", "a b"]),
        ("break foo\\ bar", ["break", "foo bar"]),
        ("break foo\\\\bar", ["break", "foo\\bar"]),
        # `#` is not a comment on a command line.
        ("p a # b", ["p", "a", "#", "b"]),
    ),
)
def test_lex_args(command_line, expected):
    assert lex_args(command_line) == expected


@pytest.mark.parametrize(
    ("command_line", "expected"),
    (
        # A trailing backslash makes `shlex.split` raise "No escaped
        # character". GDB's `string_to_argv` keeps the incomplete argument
        # instead, and so do we. See #4130.
        ("nearpc -f\\", ["nearpc", "-f"]),
        ("nearpc\\", ["nearpc"]),
        ("\\", []),
        # Likewise for an unterminated quote, which makes `shlex.split` raise
        # "No closing quotation".
        ('search -s "a b', ["search", "-s", "a b"]),
        ("search -s 'a b", ["search", "-s", "a b"]),
        ('search -s "', ["search", "-s"]),
    ),
)
def test_lex_args_is_lenient(command_line, expected):
    assert lex_args(command_line) == expected
