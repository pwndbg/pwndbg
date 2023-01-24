"""
Dynamic configuration system for pwndbg, using GDB's built-in Parameter
mechanism.

To create a new pwndbg configuration point, call ``pwndbg.gdblib.config.add_param``.

Parameters should be declared in the module in which they are primarily
used, or in this module for general-purpose parameters.

All pwndbg Parameter types are accessible via property access on this
module, for example:

    >>> pwndbg.gdblib.config.add_param('example-value', 7, 'an example')
    >>> int(pwndbg.gdblib.config.example_value)
    7
"""
import gdb

import pwndbg.decorators
import pwndbg.lib.config

config = pwndbg.lib.config.Config()

# GDB < 9 does not support PARAM_ZUINTEGER*, so we implement it by ourselves for consistency
if not hasattr(gdb, "PARAM_ZUINTEGER"):
    gdb.PARAM_ZUINTEGER = "PARAM_ZUINTEGER"
    gdb.PARAM_ZUINTEGER_UNLIMITED = "PARAM_ZUINTEGER_UNLIMITED"


# See this for details about the API of `gdb.Parameter`:
# https://sourceware.org/gdb/onlinedocs/gdb/Parameters-In-Python.html
class Parameter(gdb.Parameter):
    def __init__(self, param: pwndbg.lib.config.Parameter) -> None:
        # `set_doc`, `show_doc`, and `__doc__` must be set before `gdb.Parameter.__init__`.
        # They will be used for `help set <param>` and `help show <param>`,
        # respectively
        self.set_doc = "Set " + param.set_show_doc + "."
        self.show_doc = "Show " + param.set_show_doc + "."
        self.__doc__ = param.help_docstring or None
        self._custom_param_class = None

        if param.param_class == gdb.PARAM_ENUM:
            super().__init__(
                param.name,
                gdb.COMMAND_SUPPORT,
                param.param_class,
                param.enum_sequence,
            )
        elif (
            param.param_class == "PARAM_ZUINTEGER"
            or param.param_class == "PARAM_ZUINTEGER_UNLIMITED"
        ):
            # GDB < 9 does not support PARAM_ZUINTEGER*, so we implement it by ourselves for consistency
            self._custom_param_class = param.param_class
            super().__init__(param.name, gdb.COMMAND_SUPPORT, pwndbg.lib.config.PARAM_CLASSES[int])
        else:
            super().__init__(param.name, gdb.COMMAND_SUPPORT, param.param_class)
        self.param = param
        self.value = param.value

    @property
    def native_value(self):
        return Parameter._value_to_gdb_native(self.param.value, param_class=self.param.param_class)

    @property
    def native_default(self):
        return Parameter._value_to_gdb_native(
            self.param.default, param_class=self.param.param_class
        )

    def get_set_string(self) -> str:
        """Handles the GDB `set <param>` command"""

        # GDB will set `self.value` to the user's input
        if self.value is None and self.param.param_class in (gdb.PARAM_UINTEGER, gdb.PARAM_INTEGER):
            # Note: This is really weird, according to GDB docs, 0 should mean "unlimited" for gdb.PARAM_UINTEGER and gdb.PARAM_INTEGER, but somehow GDB sets the value to `None` actually :/
            # And hilarious thing is that GDB won't let you set the default value to `None` when you construct the `gdb.Parameter` object with `gdb.PARAM_UINTEGER` or `gdb.PARAM_INTEGER` lol
            # Maybe it's a bug of GDB?
            # Anyway, to avoid some unexpected behaviors, we'll still set `self.param.value` to 0 here.
            self.param.value = 0
        else:
            if self._custom_param_class:
                if (self._custom_param_class == "PARAM_ZUINTEGER" and self.value < 0) or (  # type: ignore
                    self._custom_param_class == "PARAM_ZUINTEGER_UNLIMITED" and self.value < -1  # type: ignore
                ):
                    err = "integer %d out of range" % self.value  # type: ignore
                    # Restore the old value
                    self.value = self.param.value
                    # GDB < 9 is too buggy, it won't handle `gdb.GdbError`..., so we return a string here
                    return err
            self.param.value = self.value

        for trigger in config.triggers[self.param.name]:
            trigger()

        # No need to print anything if this is set before we get to a prompt,
        # like if we're setting options in .gdbinit
        if not pwndbg.decorators.first_prompt:
            return ""

        return "Set %s to %r." % (self.param.set_show_doc, self.native_value)

    def get_show_string(self, svalue) -> str:
        """Handles the GDB `show <param>` command"""
        more_information_hint = " See `help set %s` for more information." % self.param.name
        if self._custom_param_class == "PARAM_ZUINTEGER_UNLIMITED" and self.value == -1:
            svalue = "unlimited"
        return "%s is %r.%s" % (
            self.param.set_show_doc.capitalize(),
            svalue,
            more_information_hint if self.__doc__ else "",
        )

    @staticmethod
    def _value_to_gdb_native(value, param_class=None):
        """Translates Python value into native GDB syntax string."""
        if isinstance(value, bool):
            # Convert booleans to "on" or "off".
            return "on" if value else "off"
        elif value is None and param_class == gdb.PARAM_AUTO_BOOLEAN:
            # None for gdb.PARAM_AUTO_BOOLEAN means "auto".
            return "auto"
        elif value == 0 and param_class in (gdb.PARAM_UINTEGER, gdb.PARAM_INTEGER):
            # 0 for gdb.PARAM_UINTEGER and gdb.PARAM_INTEGER means "unlimited".
            return "unlimited"
        elif value == -1 and param_class == gdb.PARAM_ZUINTEGER_UNLIMITED:
            # -1 for gdb.PARAM_ZUINTEGER_UNLIMITED means "unlimited".
            return "unlimited"

        # Other types pass through normally
        return value


def init_params() -> None:
    # Create a gdb.Parameter for each parameter
    for p in pwndbg.gdblib.config.params.values():
        # We don't need to store this anywhere, GDB will handle this
        Parameter(p)
