import pwndbg.color.theme as theme
import pwndbg.gdblib.config as config
from pwndbg.color import generateColorFunction

config_symbol = theme.add_color_param(
    "nearpc-symbol-color", "normal", "color for nearpc command (symbol)"
)
config_address = theme.add_color_param(
    "nearpc-address-color", "normal", "color for nearpc command (address)"
)
config_prefix = theme.add_color_param(
    "nearpc-prefix-color", "none", "color for nearpc command (prefix marker)"
)
config_syscall_name = theme.add_color_param(
    "nearpc-syscall-name-color", "red", "color for nearpc command (resolved syscall name)"
)
config_argument = theme.add_color_param(
    "nearpc-argument-color", "bold", "color for nearpc command (target argument)"
)
config_ida_anterior = theme.add_color_param(
    "nearpc-ida-anterior-color", "bold", "color for nearpc command (IDA anterior)"
)
config_branch_marker = theme.add_color_param(
    "nearpc-branch-marker-color", "normal", "color for nearpc command (branch marker line)"
)


def symbol(x):
    return generateColorFunction(config.nearpc_symbol_color)(x)


def address(x):
    return generateColorFunction(config.nearpc_address_color)(x)


def prefix(x):
    return generateColorFunction(config.nearpc_prefix_color)(x)


def syscall_name(x):
    return generateColorFunction(config.nearpc_syscall_name_color)(x)


def argument(x):
    return generateColorFunction(config.nearpc_argument_color)(x)


def ida_anterior(x):
    return generateColorFunction(config.nearpc_ida_anterior_color)(x)


def branch_marker(x):
    return generateColorFunction(config.nearpc_branch_marker_color)(x)
