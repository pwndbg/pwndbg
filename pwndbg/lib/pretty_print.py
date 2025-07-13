from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from typing import Callable
from typing import List
from typing import Optional

import pwndbg.color as color
from pwndbg.color import theme

config_property_name_color = theme.add_color_param(
    "prop-name-color",
    "bold",
    "color used to highlight the name in name-value pairs",
    help_docstring="""
Used heavily in mallocng commands.
"""
)

config_property_value_color = theme.add_color_param(
    "prop-value-color",
    "yellow",
    "color used to highlight the value in name-value pairs",
    help_docstring="""
Used heavily in mallocng commands.
"""
)

config_property_title_color = theme.add_color_param(
    "prop-title-color",
    "green",
    "color used to highlight the title of name-value pair groups",
    help_docstring="""
Used heavily in mallocng commands.
"""
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
    extra: str | List[str] = ""
    # Will print the value as hex and use the address's
    # mapping's color.
    is_addr: bool = False
    # Will turn an integer into its hex representation.
    use_hex: bool = True
    # Override the color used by from_properties().
    name_color_func: Optional[Callable[[str], str]] = None
    value_color_func: Optional[Callable[[str], str]] = None


def from_properties(
    title: str,
    properties: List[Property],
    *,
    preamble: str = "",
    value_offset: int = 14,
    extra_offset: int = 16,
    title_color_func: Optional[Callable[[str], str]] = None,
    name_color_func: Optional[Callable[[str], str]] = None,
    value_color_func: Optional[Callable[[str], str]] = None,
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
            if prop.use_hex:
                prop.value = hex(prop.value)
            else:
                prop.value = str(prop.value)
        if isinstance(prop.alt_value, int):
            if prop.use_hex:
                prop.alt_value = hex(prop.alt_value)
            else:
                prop.alt_value = str(prop.alt_value)

    indentation_str = indent_size * " "
    extra_list_pad_str = (
        indentation_str + value_offset * " " + "  " + extra_offset * " "
    )

    for prop in properties:
        # The property may override the generic color functions.
        prop_name_cfunc = prop.name_color_func if prop.name_color_func is not None else name_color_func
        prop_value_cfunc = prop.value_color_func if prop.value_color_func is not None else value_color_func

        text += (
            indentation_str
            + color.ljust_colored(prop_name_cfunc(prop.name) + ":", value_offset)
            + "  "
        )

        if prop.is_addr:
            base = 16 if prop.use_hex else 10
            colored_val = color.memory.get(int(prop.value, base))
        else:
            colored_val = prop_value_cfunc(prop.value)

        colored_alt_val = ""
        if prop.alt_value is not None:
            colored_alt_val = f" ({prop_value_cfunc(prop.alt_value)})"

        text += color.ljust_colored(colored_val + colored_alt_val, extra_offset)

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
