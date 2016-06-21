import pwndbg.config
from pwndbg.color import generateColorFunction

config_normal    = pwndbg.config.Parameter('color-hexdump-normal', 'normal', 'color for hexdump command (normal bytes)')
config_printable = pwndbg.config.Parameter('color-hexdump-printable', 'bold', 'color for hexdump command (printable characters)')
config_zero      = pwndbg.config.Parameter('color-hexdump-zero', 'red', 'color for hexdump command (zero bytes)')
config_special   = pwndbg.config.Parameter('color-hexdump-special', 'yellow', 'color for hexdump command (special bytes)')
config_offset    = pwndbg.config.Parameter('color-hexdump-offset', 'green', 'color for hexdump command (offset label)')
config_separator = pwndbg.config.Parameter('color-hexdump-separator', 'normal', 'color for hexdump command (group separator)')

def normal(x):
    return generateColorFunction(pwndbg.config.color_hexdump_normal)(x)

def printable(x):
    return generateColorFunction(pwndbg.config.color_hexdump_printable)(x)

def zero(x):
    return generateColorFunction(pwndbg.config.color_hexdump_zero)(x)

def special(x):
    return generateColorFunction(pwndbg.config.color_hexdump_special)(x)

def offset(x):
    return generateColorFunction(pwndbg.config.color_hexdump_offset)(x)

def separator(x):
    return generateColorFunction(pwndbg.config.color_hexdump_separator)(x)
