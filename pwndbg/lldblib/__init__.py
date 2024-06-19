from __future__ import annotations

import lldb

from typing_extensions import Callable

def register_class_as_cmd(debugger: lldb.SBDebugger, cmd: str, handler: Callable[..., None], path: str = None):
    name = path
    if not name:
        mod = handler.__module__
        name = handler.__qualname__
        name = f"{mod if mod else ''}.{name}"

    debugger.HandleCommand(f"command script add -c {name} -s synchronous {cmd}")
