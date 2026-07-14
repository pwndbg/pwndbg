from __future__ import annotations

import pytest

import pwndbg.color


def test_generate_color_function_valid() -> None:
    # Single valid color
    func = pwndbg.color.generate_color_function("red")
    assert callable(func)
    assert func("test") == "\x1b[31mtest\x1b[0m"

    # Multiple valid styles/colors
    func = pwndbg.color.generate_color_function("bold,red")
    assert callable(func)
    assert func("test") == "\x1b[31m\x1b[1mtest\x1b[0m\x1b[31m\x1b[0m"


def test_generate_color_function_invalid() -> None:
    # Invalid single color
    with pytest.raises(ValueError, match="Invalid color/style 'meow'"):
        pwndbg.color.generate_color_function("meow")

    # Invalid color within a list
    with pytest.raises(ValueError, match="Invalid color/style 'meow'"):
        pwndbg.color.generate_color_function("bold,meow")


def test_generate_color_function_whitespace_and_empty() -> None:
    # Handling of whitespace and trailing commas
    func = pwndbg.color.generate_color_function(" bold , red , ")
    assert callable(func)
    assert func("test") == "\x1b[31m\x1b[1mtest\x1b[0m\x1b[31m\x1b[0m"
