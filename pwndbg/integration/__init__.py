from __future__ import annotations

from dataclasses import dataclass
from typing import List
from typing import Tuple

import pwndbg
import pwndbg.lib.config
import pwndbg.lib.functions
from pwndbg.color import message


class IntegrationProvider:
    """
    A class representing an integration that provides intelligence external to GDB.
    """

    def get_symbol(self, addr: int) -> str | None:
        """
        Get a symbol at an address, or an offset from a symbol.
        """
        return None

    def get_versions(self) -> Tuple[str, ...]:
        """
        Gets any version strings relevant to the integration,
        which are used when displaying the `version` command.
        """
        return ()

    def is_in_function(self, addr: int) -> bool:
        """
        Checks if integration thinks that an address is in a function,
        which is used to determine if `tel` should try to disassemble something.

        If uncertain, it's better to default to True than to False.
        """
        return True

    def get_comment_lines(self, addr: int) -> List[str]:
        """
        Gets any comments attached to an instruction.
        """
        return []

    def decompile(self, addr: int, lines: int) -> List[str] | None:
        """
        Decompiles the code near an address given a line count.
        """
        return None

    def get_func_type(self, addr: int) -> pwndbg.lib.functions.Function | None:
        """
        Gets the type signature of a function, used for argument labeling.
        """
        return None

    def get_stack_var_name(self, addr: int) -> str | None:
        """
        Gets the name of a stack variable based on only the address of the variable.
        """
        return None


provider_name = pwndbg.config.add_param(
    "integration-provider",
    "none",
    "which provider to use for integration features",
    param_class=pwndbg.lib.config.PARAM_ENUM,
    enum_sequence=["none", "binja", "ida"],
)

symbol_lookup = pwndbg.config.add_param(
    "integration-symbol-lookup", True, "whether to use integration to look up unknown symbols"
)

smart_enhance = pwndbg.config.add_param(
    "integration-smart-enhance",
    True,
    "use integration to determine when to disassemble during enhancing",
)

function_lookup = pwndbg.config.add_param(
    "integration-function-lookup",
    True,
    "use integration to look up function type signatures",
)


# TODO: maybe create these functions dynamically since they're pretty boilerplate?
@dataclass
class ConfigurableProvider(IntegrationProvider):
    """
    A wrapper around an IntegrationProvider that skips calling functions if disabled in config.
    """

    inner: IntegrationProvider

    def get_symbol(self, addr: int) -> str | None:
        if symbol_lookup:
            return self.inner.get_symbol(addr)
        return super().get_symbol(addr)

    def get_versions(self) -> Tuple[str, ...]:
        # Doesn't make a lot of sense to make this configurable
        return self.inner.get_versions()

    def is_in_function(self, addr: int) -> bool:
        if smart_enhance:
            return self.inner.is_in_function(addr)
        return super().is_in_function(addr)

    def get_comment_lines(self, addr: int) -> List[str]:
        # This should be configured via nearpc-integration-comments instead
        return self.inner.get_comment_lines(addr)

    def decompile(self, addr: int, lines: int) -> List[str] | None:
        # This should be configured via context-integration-decompile instead
        return self.inner.decompile(addr, lines)

    def get_func_type(self, addr: int) -> pwndbg.lib.functions.Function | None:
        if function_lookup:
            return self.inner.get_func_type(addr)
        return super().get_func_type(addr)

    def get_stack_var_name(self, addr: int) -> str | None:
        return self.inner.get_stack_var_name(addr)


provider: IntegrationProvider = IntegrationProvider()


@pwndbg.config.trigger(provider_name)
def switch_providers():
    global provider
    if not provider_name.value or provider_name.value == "none":
        provider = IntegrationProvider()
    elif provider_name.value == "binja":
        # do not import at start of file to avoid circular import
        import pwndbg.integration.binja

        provider = ConfigurableProvider(pwndbg.integration.binja.BinjaProvider())
    elif provider_name.value == "ida":
        import pwndbg.integration.ida

        provider = ConfigurableProvider(pwndbg.integration.ida.IdaProvider())
    else:
        print(
            message.warn(
                f"Invalid provider {provider_name.value!r} specified. Disabling integration."
            )
        )
        provider_name.revert_default()
