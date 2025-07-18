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
    alt_value: Any = None
    extra: str | List[str] = ""
    is_addr: bool = False
    use_hex: bool = True


class PropertyPrinter:
    """
    When you have (property name, property value) pairs
    that you want to print, each on a new line.
    """

    def __init__(
        self,
        value_offset: int = 14,
        extra_offset: int = 16,
        *,
        name_color_func: Optional[Callable[[str], str]] = None,
        value_color_func: Optional[Callable[[str], str]] = None,
        section_color_func: Optional[Callable[[str], str]] = None,
        indent_size: int = 2,
    ):
        self.value_offset = value_offset
        self.extra_offset = extra_offset

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
        self.text = ""

    def add(self, prop_group: List[Property]) -> None:
        """
        Add a group of properties that should be aligned.
        """
        # Transform prop values to string representation
        for prop in prop_group:
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

        indentation_str = self.indent_level * self.indent_size * " "
        extra_list_pad_str = (
            indentation_str + self.value_offset * " " + "  " + self.extra_offset * " "
        )

        for prop in prop_group:
            self.text += (
                indentation_str
                + color.ljust_colored(self.name_color_func(prop.name) + ":", self.value_offset)
                + "  "
            )

            if prop.is_addr:
                base = 16 if prop.use_hex else 10
                colored_val = color.memory.get(int(prop.value, base))
            else:
                colored_val = self.value_color_func(prop.value)

            colored_alt_val = ""
            if prop.alt_value is not None:
                colored_alt_val = " (" + self.value_color_func(prop.alt_value) + ")"

            self.text += color.ljust_colored(colored_val + colored_alt_val, self.extra_offset)

            if isinstance(prop.extra, str):
                self.text += "  " + prop.extra
            else:
                # list of strings, we want each one under the other
                assert isinstance(prop.extra, list)

                self.text += "  " + prop.extra[0]
                for i in range(1, len(prop.extra)):
                    self.text += "\n"
                    self.text += extra_list_pad_str
                    self.text += "  " + prop.extra[i]

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
        print(self.text, end="")

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

    def start_section(self, title: str, preamble: str = "") -> None:
        """
        Start a named section of properties that will have
        increased indentation.

        Don't forget to call end_section()!
        """
        self.text += " " * self.indent_level * self.indent_size
        self.text += self.section_color_func(title)

        if preamble:
            self.text += "\n"
            self.text += " " * (self.indent_level + 1) * self.indent_size
            self.text += preamble

        self.text += "\n"
        self.indent()

    def end_section(self) -> None:
        """
        End a section.
        """
        self.unindent()
