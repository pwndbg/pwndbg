from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pwndbg
import pwndbg.color
import pwndbg.color.context
import pwndbg.color.memory
import pwndbg.lib.config
from pwndbg.color import theme

max_decimal_number = pwndbg.config.add_param(
    "max-decimal-number",
    9,
    "show all numbers greater than this in hex",
    param_class=pwndbg.lib.config.PARAM_ZUINTEGER_UNLIMITED,
    help_docstring="""
For negative numbers, their absolute value is used.

Set the parameter to 'unlimited' if you want all values in decimal.
Specially, set the parameter to zero if you want all values in hex.

The assembly instruction operands come from capstone, and are thus
not controlled by this setting. For consistency with them, leave
this setting at 9 (the default).
""",
    # We could look into also overwriting the capstone operands string, similarly
    # to what is done here: https://github.com/pwndbg/pwndbg/blob/26db4533aa08d77c4bbc359b4760a0944e0c6b23/pwndbg/aglib/disasm/arch.py#L322-L331
)


def int_to_string(num: int, adhere_to_ptrwidth: int = -1) -> str:
    """
    Converts an integer value to string.

    Decides whether to format it in decimal or
    hex depending on the max-decimal-number config.

    If adhere_to_ptrwidth is not `-1`, it should be the size of a pointer
    of the current CPU architecture in bits. Will cause the output string
    to be aligned to the pointer size. E.g. `0x00007ffff7fe36c6` instead
    of `0x7ffff7fe36c6`. If this is not -1, the int will always be hexified
    regardless of `max-decimal-number`. See also `chain-full-values`.
    """
    if adhere_to_ptrwidth != -1:
        nibble_num = adhere_to_ptrwidth * 2 // 8
        # assert (adhere_to_ptrwidth * 2) % 8 == 0
        return f"{num:#0{nibble_num + 2}x}"
    if max_decimal_number == -1:
        return f"{num}"
    if max_decimal_number == 0:
        return f"{num:#x}"
    if abs(num) > max_decimal_number:
        return f"{num:#x}"
    return f"{num}"


def int_pair_to_string(num1: int, num2: int) -> tuple[str, str]:
    """
    Converts an integer pair to a string pair.

    Decides whether to format them in decimal or
    hex depending on the max-decimal-number config.

    If either value should be hex, both are hex.
    """
    if max_decimal_number == -1:
        return f"{num1}", f"{num2}"
    if max_decimal_number == 0:
        return f"{num1:#x}", f"{num2:#x}"
    if abs(num1) > max_decimal_number or abs(num2) > max_decimal_number:
        return f"{num1:#x}", f"{num2:#x}"
    return f"{num1}", f"{num2}"


config_property_name_color = theme.add_color_param(
    "prop-name-color",
    "bold",
    "color used to highlight the name in name-value pairs",
    help_docstring="""
Used heavily in mallocng commands.
""",
)

config_property_value_color = theme.add_color_param(
    "prop-value-color",
    "yellow",
    "color used to highlight the value in name-value pairs",
    help_docstring="""
Used heavily in mallocng commands.
""",
)

config_property_title_color = theme.add_color_param(
    "prop-title-color",
    "green",
    "color used to highlight the title of name-value pair groups",
    help_docstring="""
Used heavily in mallocng commands.
""",
)


@dataclass
class Property:
    """
    A (property name, property value) pair
    with optional extra information.

    Used by from_properties().
    """

    name: str
    value: Any
    # Alternate value, will be shown in brackets e.g.
    #   slack:   0x2 (0x20)
    alt_value: Any = None
    # Extra explanation, may be list, e.g.
    #   hdr reserved: 0x5  describes: end - p - n
    #                      use ftr reserved
    extra: str | list[str] = ""
    # Will print the value as hex and use the address's
    # mapping's color.
    is_addr: bool = False
    # Will turn an integer into its hex representation.
    use_hex: bool = True
    # Override the color used by from_properties().
    name_color_func: Callable[[str], str] | None = None
    value_color_func: Callable[[str], str] | None = None


def from_properties(
    title: str,
    properties: list[Property],
    *,
    preamble: str = "",
    value_offset: int = 14,
    extra_offset: int = 16,
    title_color_func: Callable[[str], str] | None = None,
    name_color_func: Callable[[str], str] | None = None,
    value_color_func: Callable[[str], str] | None = None,
    indent_size: int = 2,
) -> str:
    """
    When you have (property name, property value) pairs
    that you want to print, each on a new line.

    A common usecase is printing a struct.

    Example:
        general
          start:          0x7ffff7ff6040
          user start:     0x7ffff7ff6040    aka `p`
          end:            0x7ffff7ff606c    start + stride - 4
          stride:         0x30              distance between adjacent slots
          user size:      0x20              aka "nominal size", `n`
          slack:          0x0 (0x0)         slot's unused memory / 0x10

    Arguments:
        title: The title of this property group. An empty string may be provided for a
            titleless group.
        properties: The list of properties to format.
        preamble: A string that will be printed between the title and the properties,
            may be used to denote the address of an object like e.g. `@ 0x408000 - 0x408fe0`
        value_offset: The number of characters from the start of the name of a property to the
            start of its value.
        extra_offset: The number of characters from the start of the value of a property to the
            start of its extra text.
        title_color_func: The function to use to color the title.
        name_color_func: The function to use to color names.
        value_color_func: The function to use to color values. This function isn't applied to
            is_addr=True properties.
        indent_size: The indentation to use i.e. the offset from the title to the names.
    """

    if name_color_func is None:
        name_color_func = config_property_name_color.color_function

    if value_color_func is None:
        value_color_func = config_property_value_color.color_function

    if title_color_func is None:
        title_color_func = config_property_title_color.color_function

    text = ""

    if title:
        text += title_color_func(title) + "\n"

    if preamble:
        text += " " * indent_size
        text += preamble + "\n"

    # Transform prop values to string representation
    for prop in properties:
        if isinstance(prop.value, int):
            prop.value = f"{prop.value:#x}" if prop.use_hex else f"{prop.value}"

        if isinstance(prop.alt_value, int):
            prop.alt_value = f"{prop.alt_value:#x}" if prop.use_hex else f"{prop.alt_value}"

    indentation_str = indent_size * " "
    extra_list_pad_str = indentation_str + value_offset * " " + "  " + extra_offset * " "

    for prop in properties:
        # The property may override the generic color functions.
        prop_name_cfunc = (
            prop.name_color_func if prop.name_color_func is not None else name_color_func
        )
        prop_value_cfunc = (
            prop.value_color_func if prop.value_color_func is not None else value_color_func
        )

        text += (
            indentation_str
            + pwndbg.color.ljust_colored(prop_name_cfunc(prop.name) + ":", value_offset)
            + "  "
        )

        if prop.is_addr:
            base = 16 if prop.use_hex else 10
            colored_val = pwndbg.color.memory.get(int(prop.value, base))
        else:
            colored_val = prop_value_cfunc(prop.value)

        colored_alt_val = ""
        if prop.alt_value is not None:
            colored_alt_val = f" ({prop_value_cfunc(prop.alt_value)})"

        text += pwndbg.color.ljust_colored(colored_val + colored_alt_val, extra_offset)

        if isinstance(prop.extra, str):
            text += "  " + prop.extra
        else:
            # list of strings, we want each one under the other
            assert isinstance(prop.extra, list)

            text += "  " + prop.extra[0]
            for i in range(1, len(prop.extra)):
                text += "\n"
                text += extra_list_pad_str
                text += "  " + prop.extra[i]

        text += "\n"

    return text


def nlines_to_range(nlines: int, current: int, total: int) -> tuple[int, int]:
    """
    When you want to get nlines of output around a certain interesting line, returns
    the range to use.

    `end - start` will not be `== nlines` only if `nlines > total`.

    The `current` line may not necessarily be centered in the range, if decentering
    it gets `end - start` closer to `nlines`.

    Arguments:
        nlines: The exact amount of lines you want.
        current: The index of the interesting line (e.g. where PC is in the source context)
        total: How many lines total you actually have.

    Returns:
        A tuple giving the range of indecies to use. The format is [start, end).
    """
    if nlines > total:
        return (0, total)

    # Note that in both calculations, ideal_end is exclusive (so we have +1)
    if nlines % 2 == 1:
        ideal_start: int = current - (nlines // 2)
        ideal_end: int = current + (nlines // 2) + 1
    else:
        # Since it is impossible to center exactly due to parity, we will make
        # `current` have the lower index because this is usually more visually pleasing.
        ideal_start = current - (nlines // 2) + 1
        ideal_end = current + (nlines // 2) + 1

    # Now it may be that we are outside of the allowed range, but if we are, we
    # are only outside on one side because we already checked `nlines > total`.
    if ideal_start < 0:
        # Now (-ideal_start) is the amount of lines we have to steal from the end
        # of the range.
        start = 0
        # ideal_end + (-ideal_start) = ideal_end - ideal_start
        end = ideal_end - ideal_start
        # We don't need to do `end = min(end, total)` because that would imply
        # that `nlines > total`.
    elif ideal_end > total:
        # Now (ideal_end - total) is the amount of lines we have to steal from the start
        # of the range.
        # ideal_start - (ideal_end - total) = ideal_start - ideal_end + total
        start = ideal_start - ideal_end + total
        end = total
        # We don't need to do `start = max(start, 0)` because that would imply
        # that `nlines > total`.
    else:
        start = ideal_start
        end = ideal_end

    return (start, end)


def format_source(source: list[str], nlines: int, interesting_line: int) -> list[str]:
    """
    Format source code.

    Use correct tab size, add the code prefix (►), add line numbers, align
    properly.

    Arguments:
        source: Already highlighted source code. List of lines.
        nlines: The amount of lines we want back.
        interesting_line: The line around which to center the output (0-indexed).
    """
    start, end = nlines_to_range(nlines, interesting_line, len(source))
    num_width = len(str(end))

    # split the code
    source = source[start:end]

    # Compute the prefix_sign length
    prefix_sign = pwndbg.color.context.prefix(str(pwndbg.config.code_prefix))
    prefix_width = len(prefix_sign)

    # Format the output
    formatted_source = []
    # line_number is 1-indexed (as source code usually is)
    interesting_line1dx: int = interesting_line + 1
    for line_number, code in enumerate(source, start=start + 1):
        # Honor the tab-size setting.
        if pwndbg.config.context_code_tabstop > 0:
            code = code.replace("\t", " " * int(pwndbg.config.context_code_tabstop))

        # Remove extra whitespace
        code = code.rstrip()

        fmt = " {prefix_sign:{prefix_width}} {line_number:>{num_width}} {code}"

        if pwndbg.config.highlight_source and line_number == interesting_line1dx:
            fmt = pwndbg.color.context.highlight(fmt)

        line = fmt.format(
            prefix_sign=prefix_sign if line_number == interesting_line1dx else "",
            prefix_width=prefix_width,
            line_number=line_number,
            num_width=num_width,
            code=code,
        )
        formatted_source.append(line)

    return formatted_source
