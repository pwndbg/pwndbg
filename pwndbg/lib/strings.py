from __future__ import annotations

import re


def strip_colors(text):
    """Remove all ANSI color codes from the text"""
    return re.sub(r"\x1b[^m]*m", "", text)
