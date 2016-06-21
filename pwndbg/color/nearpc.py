import pwndbg.config
from pwndbg.color import generateColorFunction

config_symbol       = pwndbg.config.Parameter('color-nearpc-symbol', 'normal', 'color for nearpc command (symbol)')
config_address      = pwndbg.config.Parameter('color-nearpc-address', 'normal', 'color for nearpc command (address)')
config_prefix       = pwndbg.config.Parameter('color-nearpc-prefix', 'red,bold', 'color for nearpc command (prefix marker)')
config_syscall_name = pwndbg.config.Parameter('color-nearpc-syscall-name', 'red', 'color for nearpc command (resolved syscall name)')
config_argument     = pwndbg.config.Parameter('color-nearpc-argument', 'bold', 'color for nearpc command (target argument)')
config_ida_anterior = pwndbg.config.Parameter('color-nearpc-ida-anterior', 'bold', 'color for nearpc command (IDA anterior)')

def symbol(x):
    return generateColorFunction(pwndbg.config.color_nearpc_symbol)(x)

def address(x):
    return generateColorFunction(pwndbg.config.color_nearpc_address)(x)

def prefix(x):
    return generateColorFunction(pwndbg.config.color_nearpc_prefix)(x)

def syscall_name(x):
    return generateColorFunction(pwndbg.config.color_nearpc_syscall_name)(x)

def argument(x):
    return generateColorFunction(pwndbg.config.color_nearpc_argument)(x)

def ida_anterior(x):
    return generateColorFunction(pwndbg.config.color_nearpc_ida_anterior)(x)
