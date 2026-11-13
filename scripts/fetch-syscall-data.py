#!/usr/bin/env python
"""
Fetch argument data for syscalls
"""

from __future__ import annotations

import base64
import json
from pathlib import Path

import requests

PWNDBG_ROOT: Path = Path(__file__).parent.parent
SOURCE_URL: str = (
    "https://raw.githubusercontent.com/guitmz/syscall.el/refs/heads/main/syscall-data.el"
)


def main() -> None:
    response = requests.get(SOURCE_URL)

    if response:
        tmp: str | list[str] = response.text.split("syscall-data--json")
        if len(tmp) < 2:
            print("Invalid data from source")
            return
        tmp = tmp[1].split('"')
        if len(tmp) < 2:
            print("Invalid data from source")
            return
        base64_data: str = tmp[1].strip().replace('"', "")
        if len(base64_data) == 0:
            print("Invalid data from source")
            return
        json_data: str = base64.b64decode(base64_data.encode("utf-8")).decode("utf-8")
        with open(PWNDBG_ROOT / "pwndbg" / "lib" / "syscall_data" / "data.json", "w") as file:
            json.dump(json.loads(json_data), file, indent=4)
    else:
        print("Unable to fetch source")
        return


if __name__ == "__main__":
    main()
