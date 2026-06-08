from __future__ import annotations

from io import StringIO

from rich.console import Console
from rich.console import RenderableType


def rich_to_str(renderable: RenderableType, *args, **kwargs) -> str:
    """
    Render something with `rich`, to a string.
    """
    with StringIO() as rendered:
        c = Console(*args, **kwargs, file=rendered)
        c.print(renderable)
        return rendered.getvalue()
