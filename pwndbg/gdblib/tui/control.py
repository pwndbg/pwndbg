from __future__ import annotations

import gdb


class ControlTUIWindow:
    _tui_window: "gdb.TuiWindow"
    _button_text: str = "[←]  [→]"
    # Map from command to the span of the button in the _button_text.
    # The span is represented as (start, end) where start is the index
    # of the first character of the button and end is the index of the
    # last character of the button to react to on mouse click.
    _button_spans = {"contextprev": (0, 2), "contextnext": (5, 7)}

    def __init__(self, tui_window: "gdb.TuiWindow") -> None:
        self._tui_window = tui_window
        self._tui_window.title = "history"

    def close(self) -> None:
        pass

    def render(self) -> None:
        self._tui_window.write(self._button_text, True)

    def hscroll(self, num: int) -> None:
        pass

    def vscroll(self, num: int) -> None:
        pass

    def click(self, x: int, y: int, button: int) -> None:
        # button specifies which mouse button was used, whose values can be 1 (left), 2 (middle), or 3 (right).
        if button != 1:
            return

        for command, (start, end) in self._button_spans.items():
            start_x = start % self._tui_window.width
            end_x = end % self._tui_window.width
            start_y = start // self._tui_window.width
            end_y = end // self._tui_window.width
            if start_x <= x <= end_x and start_y <= y <= end_y:
                gdb.execute(command, to_string=True)
                break


if hasattr(gdb, "register_window_type"):
    gdb.register_window_type("pwndbg_control", ControlTUIWindow)
