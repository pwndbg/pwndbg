from __future__ import annotations

import os
from dataclasses import dataclass

BASE_PATH = os.path.join("docs", "configuration")


@dataclass
class ExtractedParam:
    name: str
    # Scope is calculated from the json
    # scope: str
    set_show_doc: str
    help_docstring: str


def extracted_filename(debugger: str) -> str:
    return os.path.join("scripts", "_docs", debugger + "_configuration.json")
