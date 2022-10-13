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

PARAM_CLASSES = {
    # The Python boolean values, True and False are the only valid values.
    bool: gdb.PARAM_BOOLEAN,
    # This is like PARAM_INTEGER, except 0 is interpreted as itself.
    int: gdb.PARAM_ZINTEGER,
    # When the user modifies the string, any escape sequences,
    # such as ‘\t’, ‘\f’, and octal escapes, are translated into
    # corresponding characters and encoded into the current host charset.
    str: gdb.PARAM_STRING,
}


# See this for details about the API of `gdb.Parameter`:
# https://sourceware.org/gdb/onlinedocs/gdb/Parameters-In-Python.html
class Parameter(gdb.Parameter):
    def __init__(self, param: pwndbg.lib.config.Parameter):
        self.param = param

        # `set_doc` and `show_doc` must be set before `gdb.Parameter.__init__`.
        # They will be used for `help set <param>` and `help show <param>`,
        # respectively
        self.set_doc = "Set " + self.param.docstring
        self.show_doc = "Show " + self.param.docstring
        super().__init__(self.param.name, gdb.COMMAND_SUPPORT, self._param_class())

    def _param_class(self):
        for k, v in PARAM_CLASSES.items():
            if isinstance(self.param.value, k):
                return v

    @property
    def native_value(self):
        return Parameter._value_to_gdb_native(self.param.value)

    @property
    def native_default(self):
        return Parameter._value_to_gdb_native(self.param.default)

    def get_set_string(self):
        """Handles the GDB `set <param>` command"""

        # GDB will set `self.value` to the user's input
        self.param.value = self.value

        for trigger in config.triggers[self.param.name]:
            trigger()

        # No need to print anything if this is set before we get to a prompt,
        # like if we're setting options in .gdbinit
        if not pwndbg.decorators.first_prompt:
            return ""

        return "Set %s to %r" % (self.param.docstring, self.param.value)

    @staticmethod
    def _value_to_gdb_native(value):
        """Translates Python value into native GDB syntax string."""
        # Convert booleans to "on" or "off". Other types pass through normally
        if isinstance(value, bool):
            return "on" if value else "off"

        return value


def init_params():
    # Create a gdb.Parameter for each parameter
    for p in pwndbg.gdblib.config.params.values():
        # We don't need to store this anywhere, GDB will handle this
        Parameter(p)
