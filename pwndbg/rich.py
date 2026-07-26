from __future__ import annotations

from io import StringIO

from rich.console import Console
from rich.console import RenderableType

from pwndbg.ui import get_window_size


def rich_to_str(
    renderable: RenderableType,
    **kwargs,
) -> str:
    """
    Render something with `rich`, to a string.
    """
    with StringIO() as rendered:
        c = Console(
            file=rendered,
            width=get_window_size()[1],
            force_terminal=True,
            **kwargs,
        )
        c.print(renderable)
        return rendered.getvalue()
