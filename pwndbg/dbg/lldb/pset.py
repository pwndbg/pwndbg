from __future__ import annotations

import argparse
from typing import Any

import pwndbg
import pwndbg.color.message as message
import pwndbg.commands
import pwndbg.lib.config as cfg

parser = argparse.ArgumentParser(description="Changes a Pwndbg setting.")
parser.add_argument(
    "name",
    type=str,
    default=None,
    help="Name of the setting to be changed",
)
parser.add_argument(
    "value",
    type=str,
    default=None,
    help="Value to change the setting into",
)


@pwndbg.commands.ArgparsedCommand(parser)
def pset(name, value):
    name = name.replace("-", "_")
    if name not in pwndbg.config.params:
        print(message.error(f"Unknown setting '{name}'"))
        return

    param = pwndbg.config.params[name]
    try:
        new_value = parse_value(param, value)
    except InvalidParse:
        print(message.error("Invalid value '{value}' for setting '{name}': {e.message}"))
        return

    param.value = new_value
    for trigger in pwndbg.config.triggers[param.name]:
        trigger()


class InvalidParse(Exception):
    pass


def parse_value(param: pwndbg.lib.config.Parameter, expression: str) -> Any:
    param_class = param.param_class
    if param_class == cfg.PARAM_BOOLEAN:
        if expression == "on":
            return True
        elif expression == "off":
            return False
        raise InvalidParse("expected 'on' or 'off'")

    if param_class == cfg.PARAM_ZINTEGER:
        try:
            return int(expression, 0)
        except ValueError:
            raise InvalidParse("expected an integer value")
    elif param_class == cfg.PARAM_STRING:
        # We have to resolve any escape sequences that may present in the string
        # we received as our expression. Exactly which escape sequences should
        # be handled is not specified, by either us or GDB, which we base this
        # behavior on, even in the LLDB version.
        #
        # Ultimately, we use the native handling of escape sequences in the
        # "unicode_escape" decoder, and hope that it's good enough. Keep in mind
        # that what we're doing here is encoding the string to an ASCII string
        # with unicode escape sequences, and then decoding it as an ASCII string
        # with escape sequences. This allows us to retain any unicode originally
        # in the string, while at the same time resolving all escape sequences
        # in the original string.
        return expression.encode("ascii", "backslashreplace").decode("unicode_escape")
    elif param_class == cfg.PARAM_ZUINTEGER or param_class == cfg.PARAM_ZUINTEGER_UNLIMITED:
        try:
            value = int(expression, 0)
            if value < 0:
                raise InvalidParse("value must be greater than or equal to zero")
            return value
        except ValueError:
            raise InvalidParse("expected an integer value")
    elif param_class == cfg.PARAM_ENUM:
        if expression not in param.enum_sequence:
            names = ", ".join([f"'{name}'" for name in param.enum_sequence])
            raise InvalidParse(f"expected one of {names}")
        return expression
    elif param_class == cfg.PARAM_OPTIONAL_FILENAME:
        # We just hope the name is correct :)
        return expression
    elif param_class == cfg.PARAM_AUTO_BOOLEAN:
        if expression == "on":
            return True
        elif expression == "off":
            return False
        elif expression == "auto":
            return None
        raise InvalidParse("expected 'on', 'off', or 'auto'")
    elif param_class == cfg.PARAM_INTEGER:
        try:
            value = int(expression, 0)
            if value == 0:
                raise InvalidParse("value must not be zero")
            return value
        except ValueError:
            raise InvalidParse("expected an integer value")
    elif param_class == cfg.PARAM_UINTEGER:
        try:
            value = int(expression, 0)
            if value <= 0:
                raise InvalidParse("value must be greater than zero")
            return value
        except ValueError:
            raise InvalidParse("expected an integer value")

    raise NotImplementedError(f"Unknown parameter class {param_class}")
