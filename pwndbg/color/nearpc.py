import pwndbg.config as config
import pwndbg.color.theme as theme
from pwndbg.color import generateColorFunction

config_symbol       = theme.Parameter('nearpc-symbol-color', 'normal', 'color for nearpc command (symbol)')
config_address      = theme.Parameter('nearpc-address-color', 'normal', 'color for nearpc command (address)')
config_prefix       = theme.Parameter('nearpc-prefix-color', 'red,bold', 'color for nearpc command (prefix marker)')
config_syscall_name = theme.Parameter('nearpc-syscall-name-color', 'red', 'color for nearpc command (resolved syscall name)')
config_argument     = theme.Parameter('nearpc-argument-color', 'bold', 'color for nearpc command (target argument)')
config_ida_anterior = theme.Parameter('nearpc-ida-anterior-color', 'bold', 'color for nearpc command (IDA anterior)')

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
