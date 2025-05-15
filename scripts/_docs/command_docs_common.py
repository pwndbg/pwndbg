from typing import Tuple
from dataclasses import dataclass
import re
import os

BASE_PATH = os.path.join("docs", "commands")
OUT_BASE = "_commands.json"

@dataclass
class ExtractedCommand:
    name: str
    category: str
    filename: str
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
