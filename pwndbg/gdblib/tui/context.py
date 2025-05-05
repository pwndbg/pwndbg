from __future__ import annotations

import re
from typing import Callable
from typing import List
from typing import Pattern

import gdb

import pwndbg
from pwndbg.color import message
from pwndbg.commands.context import context
from pwndbg.commands.context import context_sections
from pwndbg.commands.context import contextoutput
from pwndbg.commands.context import resetcontextoutput


class ContextTUIWindow:
    _tui_window: "gdb.TuiWindow"
    _section: str
    _lines: List[str]
    _blank_line_lengths: List[int]
    _longest_line: int
    _before_prompt_listener: Callable[[None], object]
    _vscroll_start: int
    _hscroll_start: int
    _old_width: int
    _ansi_escape_regex: Pattern[str]
    _enabled: bool

    _static_enabled: bool = True
    _context_windows: List[ContextTUIWindow] = []

    def __init__(self, tui_window: "gdb.TuiWindow", section: str) -> None:
        self._tui_window = tui_window
        self._section = section
        self._tui_window.title = section
        self._lines = []
        self._blank_line_lengths = []
        self._longest_line = 0
        self._before_prompt_listener = self._before_prompt
        self._old_width = 0
        self._vscroll_start = 0
        self._hscroll_start = 0
        self._ansi_escape_regex = re.compile(r"\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])")
        self._enabled = False
        self._enable()
        gdb.events.before_prompt.connect(self._before_prompt_listener)
        ContextTUIWindow._context_windows.append(self)

    def close(self) -> None:
        ContextTUIWindow._context_windows.remove(self)
        if self._enabled:
            self._disable()
        gdb.events.before_prompt.disconnect(self._before_prompt_listener)

    def render(self) -> None:
        # render is called again after the TUI was disabled
        self._verify_enabled_state()

        if (
            not self._lines
            and self._section != "legend"
            and self._section not in str(pwndbg.config.context_sections)
        ):
            self._tui_window.write(
                message.warn(
                    f"Section '{self._section}' is not in 'context-sections' and won't be updated automatically."
                ),
                True,
            )
            return

        height = self._tui_window.height
        width = self._tui_window.width
        start = self._vscroll_start
        end = start + height
        lines = self._lines[start:end]
        output = ""
        for idx, line in enumerate(lines):
            if self._blank_line_lengths[start + idx] < width:
                line = self._ansi_substr(line, self._hscroll_start, len(line)) + "\n"
            else:
                line = self._ansi_substr(line, self._hscroll_start, self._hscroll_start + width)
                if self._blank_line_lengths[start + idx] - self._hscroll_start < width:
                    line += "\n"
            output += line
        self._tui_window.write(output, True)

    def hscroll(self, num: int) -> None:
        old_start = self._hscroll_start
        max_start = max(0, self._longest_line - self._tui_window.width)
        self._hscroll_start = min(max(0, self._hscroll_start + num), max_start)
        if old_start != self._hscroll_start:
            self.render()

    def vscroll(self, num: int) -> None:
        old_start = self._vscroll_start
        max_start = max(0, len(self._lines) - self._tui_window.height)
        self._vscroll_start = min(max(0, self._vscroll_start + num), max_start)
        if old_start != self._vscroll_start:
            self.render()

    def click(self, x: int, y: int, button: int) -> None:
        gdb.execute(f"focus pwndbg_{self._section}", to_string=True)

    def _before_prompt(self):
        if not self._verify_enabled_state():
            return
        self._update()
        self.render()

    def _enable(self):
        self._update()
        self._enabled = True

    def _disable(self):
        self._old_width = 0
        resetcontextoutput(self._section)
        self._enabled = False

    def _update(self):
        if self._old_width != self._tui_window.width:
            self._old_width = self._tui_window.width
            contextoutput(
                self._section,
                self._receive_context_output,
                clearing=True,
                banner="none",
                width=self._old_width - 1,
            )

    def _receive_context_output(self, data: str):
        if not self._verify_enabled_state():
            return
        self._lines = data.strip("\n").split("\n")
        self._blank_line_lengths = [
            len(self._ansi_escape_regex.sub("", line)) for line in self._lines
        ]
        self._longest_line = max(self._blank_line_lengths)
        self.render()

    def _verify_enabled_state(self) -> bool:
        is_valid = self._tui_window.is_valid()
        if is_valid:
            if not self._enabled:
                for context_window in ContextTUIWindow._context_windows:
                    context_window._enable()
                if not ContextTUIWindow._static_enabled and pwndbg.dbg.selected_inferior().alive():
                    context()
                ContextTUIWindow._static_enabled = True
        else:
            if self._enabled:
                self._disable()
                ContextTUIWindow._static_enabled = False
        return is_valid

    def _ansi_substr(self, line: str, start_char: int, end_char: int) -> str:
        ansi_escape_before_start = ""
        ansi_escape_after_end = ""
        colored_start_idx = 0
        colored_end_idx = 0
        colored_idx = 0
        char_count = 0
        while colored_idx < len(line):
            c = line[colored_idx]
            # collect all ansi escape sequences before the start of the colored substring
            # as well as after the end of the colored substring
            # skip them while counting the characters to slice
            if c == "\x1b":
                m = self._ansi_escape_regex.match(line[colored_idx:])
                if m:
                    colored_idx += m.end()
                    if char_count < start_char:
                        ansi_escape_before_start += m.group()
                        colored_start_idx += m.end()
                    if char_count < end_char:
                        colored_end_idx += m.end()
                    if colored_idx > colored_end_idx:
                        ansi_escape_after_end += m.group()
                    continue

            if char_count < start_char:
                colored_start_idx += 1
            if char_count < end_char:
                colored_end_idx += 1
                char_count += 1
            colored_idx += 1
        return (
            (
                ansi_escape_before_start
                + line[colored_start_idx:colored_end_idx]
                + ansi_escape_after_end
                # Workaround for display bug in GDB TUI ANSI escape sequence translation.
                # Only resetting the foreground or background colors results in
                # generating wrong colors in the TUI.
                # The workaround is to avoid the sequences that only reset the colors
                # and replace them with a full reset sequence.
                # It resets other styling attributes like bold too but it's better
                # than having wrong colors.
                # https://github.com/pwndbg/pwndbg/issues/2654
            )
            .replace("\x1b[39m", "\x1b[0m")
            .replace("\x1b[49m", "\x1b[0m")
            .replace("\x1b[39;49m", "\x1b[0m")
        )


if hasattr(gdb, "register_window_type"):
    sections = ["legend"] + [
        section.__name__.replace("context_", "") for section in context_sections.values()
    ]
    for section_name in sections:
        # https://github.com/python/mypy/issues/12557
        target_func: Callable[..., gdb._Window] = (
            lambda window, section_name=section_name: ContextTUIWindow(window, section_name)
        )
        gdb.register_window_type(
            "pwndbg_" + section_name,
            target_func,
        )
