from __future__ import annotations

from dataclasses import dataclass
from typing import Any
from typing import Callable
from typing import List
from typing import Optional

import pwndbg.color as color


@dataclass
class Property:
    """
    A (property name, property value) pair
    with optional extra information.

    Used by the PropertyPrinter.
    """

    name: str
    value: Any
    extra: str = ""
    is_addr: bool = False
    use_hex: bool = True


class PropertyPrinter:
    """
    When you have (property name, property value) pairs
    that you want to print, each on a new line.
    """

    def __init__(
        self,
        *,
        name_color_func: Optional[Callable[[str], str]] = None,
        value_color_func: Optional[Callable[[str], str]] = None,
        section_color_func: Optional[Callable[[str], str]] = None,
        indent_size: int = 2,
    ):
        self.name_color_func = name_color_func
        if self.name_color_func is None:
            self.name_color_func = color.bold

        self.value_color_func = value_color_func
        if self.value_color_func is None:
            self.value_color_func = color.yellow

        self.section_color_func = section_color_func
        if self.section_color_func is None:
            self.section_color_func = color.green

        self.indent_size = indent_size

        self.indent_level = 0
        self.padding = 2
        self.text = ""

    def add(self, prop_group: List[Property]) -> None:
        """
        Add a group of properties that should be aligned.
        """
        max_name_len = max(len(self.name_color_func(prop.name)) for prop in prop_group)

        for prop in prop_group:
            self.text += self.indent_level * self.indent_size * " "
            colored_name = self.name_color_func(prop.name) + ":"
            self.text += colored_name.ljust(max_name_len + 1, " ")
            self.text += self.padding * " "

            if prop.is_addr:
                self.text += color.memory.get(prop.value)
            else:
                if isinstance(prop.value, int) and prop.use_hex:
                    val = hex(prop.value)
                else:
                    val = prop.value
                self.text += self.value_color_func(val)

            self.text += " " + prop.extra

            self.text += "\n"

    def dump(self) -> str:
        """
        Return the built up string.
        """
        return self.text

    def print(self) -> None:
        """
        Print the built up string.
        """
        print(self.text)

    def clear(self) -> None:
        """
        Clear the built up string.
        """
        self.text = ""

    def indent(self) -> None:
        """
        Increase indentation level by one.
        """
        self.indent_level += 1

    def unindent(self) -> None:
        """
        Decrease indentation level by one.
        """
        self.indent_level -= 1
        assert self.indent_level >= 0

    def write(self, string: str) -> None:
        """
        Write raw string to the PropertyPrinter.
        """
        self.text += string

    def start_section(self, title: str) -> None:
        """
        Start a named section of properties that will have
        increased indentation.

        Don't forget to call end_section()!
        """
        self.text += self.section_color_func(title) + "\n"
        self.indent()

    def end_section(self) -> None:
        """
        End a section.
        """
        self.unindent()

    def set_padding(self, pad: int) -> None:
        """
        Set the distance between the end of the longest
        property name and the start of the value column.
        """
        self.padding = pad
