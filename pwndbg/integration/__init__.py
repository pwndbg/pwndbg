from __future__ import annotations

from typing import List
from typing import Tuple

import pwndbg
import pwndbg.lib.config
import pwndbg.lib.functions
from pwndbg.color import message


class IntegrationProvider:
    def get_symbol(self, addr: int) -> str | None:
        """
        Get a symbol at an address, or an offset from a symbol.
        """
        return None

    def get_versions(self) -> Tuple[str, ...]:
        return ()

    def is_in_function(self, addr: int) -> bool:
        return True

    def get_comment_lines(self, addr: int) -> List[str]:
        return []

    def decompile(self, addr: int, lines: int) -> List[str] | None:
        return None

    def get_func_type(self, addr: int) -> pwndbg.lib.functions.Function | None:
        return None


provider_name = pwndbg.config.add_param(
    "integration-provider",
    "none",
    "which provider to use for integration features",
    param_class=pwndbg.lib.config.PARAM_ENUM,
    enum_sequence=["none", "binja", "ida"],
)

provider: IntegrationProvider = IntegrationProvider()


@pwndbg.config.trigger(provider_name)
def switch_providers():
    global provider
    if not provider_name.value or provider_name.value == "none":
        provider = IntegrationProvider()
    elif provider_name.value == "binja":
        # do not import at start of file to avoid circular import
        import pwndbg.integration.binja

        provider = pwndbg.integration.binja.BinjaProvider()
    elif provider_name.value == "ida":
        import pwndbg.integration.ida

        provider = pwndbg.integration.ida.IdaProvider()
    else:
        print(
            message.warn(
                f"Invalid provider {provider_name.value!r} specified. Disabling integration."
            )
        )
        provider_name.revert_default()
