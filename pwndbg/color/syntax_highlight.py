from __future__ import annotations

import fnmatch
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

pwndbg.config.add_param("syntax-highlight", True, "source code / assembly syntax highlight")
style = theme.add_param(
    "syntax-highlight-style",
    "monokai",
    "source code / assembly syntax highlight stylename of pygments module",
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


def _fn_matches(filename, pattern):
    # faster alternative to the naive regex matching algorithm that pygments uses
    # most of the regexs are of the form "*.<extension>", which can be converted to a simple string match
    extension = pattern[2:]
    if pattern.isascii() and pattern[0] == "*" and pattern[1] == "." and extension.isalnum():
        # to avoid an extra string copy, we also need to check whether the filename has a '.' before the extension
        return filename.endswith(extension) and filename[-len(extension) - 1] == "."

    # fall back to slow regex
    return re.match(fnmatch.translate(pattern), filename)


def _pygments_get_lexer_for_filename(filename, code, **options):
    """
    A faster alternative to pygment's get_lexer_for_filename only checks the
    built-in lexers unless a match is not found, in which case it falls back to
    pygment's get_lexer_for_filename, which also checks for plugin lexers.
    """

    # fall back to slow method if there are multiple matches
    one_match = False
    matched_lexer = ""
    fn = os.path.basename(filename)
    for name, _, filenames, _ in pygments.lexers.get_all_lexers(plugins=False):
        for filename in filenames:
            if _fn_matches(fn, filename):
                if one_match:
                    # already seen one match, this is a second match
                    one_match = False
                    break
                one_match = True
                matched_lexer = name
    if one_match:
        return pygments.lexers.get_lexer_by_name(matched_lexer, **options)
    else:
        # either we can't find it or there are multiple matches to choose from
        return pygments.lexers.guess_lexer_for_filename(filename, code, **options)


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
            lexer = _pygments_get_lexer_for_filename(filename, code, stripnl=False)
        except pygments.util.ClassNotFound:
            # no lexer for this file or invalid style
            pass

    if lexer:
        lexer_cache[filename] = lexer

        code = pygments.highlight(code, lexer, formatter).rstrip()

    return code
