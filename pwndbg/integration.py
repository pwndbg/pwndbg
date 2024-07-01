from __future__ import annotations

from typing import List
from typing import Tuple

import pwndbg


class IntegrationProvider:
    def get_symbol(self, addr: int) -> str | None:
        """
        Get a symbol at an address, or an offset from a symbol.
        """
        return None

    def get_versions(self) -> Tuple[str, ...]:
        return ()

    def is_in_function(self, addr: int) -> bool:
        return False

    def get_comment_lines(self, addr: int) -> List[str]:
        return []

    def decompile(self, addr: int, lines: int) -> List[str] | None:
        return None


provider_name = pwndbg.config.add_param(
    "integration-provider",
    "none",
    "Which provider to use for integration features. Valid values are: none, binja, ida",
)

provider: IntegrationProvider = IntegrationProvider()


@pwndbg.config.trigger(provider_name)
def switch_providers():
    global provider
    if provider_name.value == "none":
        provider = IntegrationProvider()
    elif provider_name.value == "binja":
        # do not import at start of file to avoid circular import
        import pwndbg.binja

        provider = pwndbg.binja.BinjaProvider()
    elif provider_name.value == "ida":
        import pwndbg.ida

        provider = pwndbg.ida.IdaProvider()
    else:
        raise ValueError(f"Invalid provider {provider!r} specified.")
