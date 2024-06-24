from __future__ import annotations

import os.path
import re
from typing import Any
from typing import Dict

import pygments
import pygments.formatters
import pygments.lexers
import pygments.util
from pwnlib.lexer import PwntoolsLexer

import pwndbg
from pwndbg.color import disable_colors
from pwndbg.color import message
from pwndbg.color import theme

pwndbg.config.add_param("syntax-highlight", True, "Source code / assembly syntax highlight")
style = theme.add_param(
    "syntax-highlight-style",
    "monokai",
    "Source code / assembly syntax highlight stylename of pygments module",
)

formatter = pygments.formatters.Terminal256Formatter(style=str(style))
pwntools_lexer = PwntoolsLexer()
lexer_cache: Dict[str, Any] = {}


@pwndbg.config.trigger(style)
def check_style() -> None:
    global formatter
    try:
        formatter = pygments.formatters.Terminal256Formatter(style=str(style))

        # Reset the highlighted source cache
        from pwndbg.commands.context import get_highlight_source

        get_highlight_source.cache.clear()
    except pygments.util.ClassNotFound:
        print(
            message.warn(f"The pygment formatter style '{style}' is not found, restore to default")
        )
        style.revert_default()


def syntax_highlight(code: str, filename: str = ".asm") -> str:
    # No syntax highlight if pygment is not installed
    if disable_colors:
        return code

    filename = os.path.basename(filename)

    lexer = lexer_cache.get(filename, None)

    # If source code is asm, use our customized lexer.
    # Note: We can not register our Lexer to pygments and use their APIs,
    # since the pygment only search the lexers installed via setuptools.
    if not lexer:
        for glob_pat in PwntoolsLexer.filenames:
            pat = "^" + glob_pat.replace(".", r"\.").replace("*", r".*") + "$"
            if re.match(pat, filename):
                lexer = pwntools_lexer
                break

    if not lexer:
        try:
            lexer = pygments.lexers.guess_lexer_for_filename(filename, code, stripnl=False)
        except pygments.util.ClassNotFound:
            # no lexer for this file or invalid style
            pass

    if lexer:
        lexer_cache[filename] = lexer

        code = pygments.highlight(code, lexer, formatter).rstrip()

    return code
