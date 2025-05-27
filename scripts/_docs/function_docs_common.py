from __future__ import annotations

import os
from dataclasses import dataclass

BASE_PATH = os.path.join("docs", "functions")


@dataclass
class ExtractedFunction:
    name: str
    signature: str
    docstring: str


def extracted_filename(debugger: str) -> str:
    return os.path.join("scripts", "_docs", debugger + "_functions.json")
