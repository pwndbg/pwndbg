from __future__ import annotations

import re
import shlex


def strip_colors(text):
    """Remove all ANSI color codes from the text"""
    return re.sub(r"\x1b[^m]*m", "", text)


def lex_args(command_line: str) -> list[str]:
    """
    Split a command line into arguments, the way a POSIX shell would.

    Unlike `shlex.split`, this never raises on a malformed command line. A
    trailing backslash or an unterminated quote simply yields the incomplete
    argument the lexer had accumulated when it ran out of input, which is what
    GDB's `string_to_argv` does.
    """
    lexer = shlex.shlex(command_line, posix=True)
    lexer.whitespace_split = True
    # Command lines have no comments, `#` is just an ordinary character.
    lexer.commenters = ""

    args: list[str] = []
    while True:
        try:
            arg = lexer.get_token()
        except ValueError:
            # The input ended in the middle of an escape sequence or of a
            # quoted string. Keep whatever came before it.
            if lexer.token:
                args.append(lexer.token)
            break

        if arg is None:
            break
        args.append(arg)

    return args
