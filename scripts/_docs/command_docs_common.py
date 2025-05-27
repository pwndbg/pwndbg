from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Tuple

BASE_PATH = os.path.join("docs", "commands")


@dataclass
class ExtractedCommand:
    name: str
    category: str
    filename: str
    description: str
    aliases: list[str]
    examples: str
    notes: str
    pure_epilog: str
    usage: str
    positionals: list[Tuple[str, str]]
    optionals: list[Tuple[str, str, str]]


def category_to_folder_name(category) -> str:
    folder = category.lower()
    folder = re.sub(r"[ /]", "_", folder)  # replace all spaces and / with _
    # Don't allow wacky characters for folder names. If you hit this assert, feel free
    # to update the regex above to sanitize the category name.
    assert all(c.isalnum() or c == "_" for c in folder)
    return folder


def extracted_filename(debugger: str) -> str:
    return os.path.join("scripts", "_docs", debugger + "_commands.json")
