from __future__ import annotations

from typing import List

from pwndbg import config
from pwndbg.color import generateColorFunction
from pwndbg.color import theme
from pwndbg.lib.regs import BitFlags

config_prefix_color = theme.add_color_param(
    "code-prefix-color", "none", "color for 'context code' command (prefix marker)"
)
config_highlight_color = theme.add_color_param(
    "highlight-color", "green,bold", "color added to highlights like source/pc"
)
config_register_color = theme.add_color_param(
    "context-register-color", "bold", "color for registers label"
)
config_flag_value_color = theme.add_color_param(
    "context-flag-value-color", "none", "color for flags register (register value)"
)
config_flag_bracket_color = theme.add_color_param(
    "context-flag-bracket-color", "none", "color for flags register (bracket)"
)
config_flag_set_color = theme.add_color_param(
    "context-flag-set-color", "green,bold", "color for flags register (flag set)"
)
config_flag_unset_color = theme.add_color_param(
    "context-flag-unset-color", "red", "color for flags register (flag unset)"
)
config_flag_changed_color = theme.add_color_param(
    "context-flag-changed-color", "underline", "color for flags register (flag changed)"
)
config_banner_color = theme.add_color_param("banner-color", "blue", "color for banner line")
config_banner_title = theme.add_color_param("banner-title-color", "none", "color for banner title")
config_register_changed_color = theme.add_color_param(
    "context-register-changed-color", "red", "color for registers label (change marker)"
)
config_register_changed_marker = theme.add_param(
    "context-register-changed-marker", "*", "change marker for registers label"
)
config_comment = theme.add_color_param("comment-color", "gray", "color for comment")


def prefix(x: object) -> str:
    return generateColorFunction(config.code_prefix_color)(x)


def highlight(x: object) -> str:
    return generateColorFunction(config.highlight_color)(x)


def register(x: object) -> str:
    return generateColorFunction(config.context_register_color)(x)


def register_changed(x: object) -> str:
    return generateColorFunction(config.context_register_changed_color)(x)


def flag_bracket(x: object) -> str:
    return generateColorFunction(config.context_flag_bracket_color)(x)


def flag_value(x: object) -> str:
    return generateColorFunction(config.context_flag_value_color)(x)


def flag_set(x: object) -> str:
    return generateColorFunction(config.context_flag_set_color)(x)


def flag_unset(x: object) -> str:
    return generateColorFunction(config.context_flag_unset_color)(x)


def flag_changed(x: object) -> str:
    return generateColorFunction(config.context_flag_changed_color)(x)


def banner(x: object) -> str:
    return generateColorFunction(config.banner_color)(x)


def banner_title(x: object) -> str:
    return generateColorFunction(config.banner_title_color)(x)


def comment(x: object) -> str:
    return generateColorFunction(config.comment_color)(x)


def format_flags(value: int | None, flags: BitFlags, last: int | None = None):
    if value is None:
        return "<unavailable>"

    desc = flag_value("%#x" % value)
    if not flags:
        return desc

    names: List[str] = []
    for name, bit in flags.items():
        # If the size is not specified, assume it's 1
        if isinstance(bit, int):
            size = 1
        else:
            assert len(bit) == 2
            size = bit[1]
            bit = bit[0]

        mask = (1 << size) - 1
        flag_val = (value >> bit) & mask

        # If the bitfield is larger than a single bit, we can't communicate the value
        # with just the case of the name, so append the actual value
        if size > 1:
            name = f"{name}:{flag_val}"

        if flag_val == 0:
            name = flag_unset(name.lower())
        else:
            name = flag_set(name.upper())

        if last is not None and flag_val != (last >> bit) & mask:
            name = flag_changed(name)
        names.append(name)

    return f"{desc} {flag_bracket('[')} {' '.join(names)} {flag_bracket(']')}"
