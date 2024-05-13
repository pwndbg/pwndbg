from __future__ import annotations

import zlib
from collections import UserDict
from typing import Any
from typing import Dict


def parse_config(config_text: bytes) -> Dict[str, str]:
    res: Dict[str, str] = {}

    for line in config_text.split(b"\n"):
        if b"=" in line:
            config_name, config_val = line.split(b"=", 1)
            res[config_name.decode("ascii")] = config_val.decode("ascii")

    return res


def parse_compresed_config(compressed_config: bytes) -> Dict[str, str]:
    config_text = zlib.decompress(compressed_config, 16)
    return parse_config(config_text)


def config_to_key(name: str) -> str:
    return "CONFIG_" + name.upper()


class Kconfig(UserDict):  # type: ignore[type-arg]
    def __init__(self, compressed_config: bytes, *args: Any, **kwargs: Any) -> None:
        super().__init__(*args, **kwargs)
        self.data = parse_compresed_config(compressed_config)

    def get_key(self, name: str) -> str | None:
        # First attempt to lookup the value assuming the user passed in a name
        # like 'debug_info', then attempt to lookup the value assuming the user
        # passed in a value like `config_debug_info` or `CONFIG_DEBUG_INFO`
        key = config_to_key(name)
        if key in self.data:
            return key
        elif name.upper() in self.data:
            return name.upper()
        elif name in self.data:
            return name

        return None

    def __getitem__(self, name: str):
        key = self.get_key(name)
        if key:
            return self.data[key]

        raise KeyError(f"Key {name} not found")

    def __contains__(self, name: object) -> bool:
        if not isinstance(name, str):
            return False
        return self.get_key(name) is not None

    def __getattr__(self, name: str):
        return self.get(name)
