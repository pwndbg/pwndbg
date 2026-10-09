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
        kwargs["width"] = kwargs.get("width") or get_window_size()[1]
        c = Console(
            **kwargs,
            file=rendered,
            force_terminal=True,
        )
        c.print(renderable)
        return rendered.getvalue()
