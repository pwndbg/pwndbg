from __future__ import annotations

from typing import Any

import lldb


def register_class_as_cmd(debugger: lldb.SBDebugger, cmd: str, handler: Any, path: str = None):
    name = path
    if not name:
        mod = handler.__module__
        name = handler.__qualname__
        name = f"{mod if mod else ''}.{name}"

    debugger.HandleCommand(f"command script add -c {name} -s synchronous {cmd}")
