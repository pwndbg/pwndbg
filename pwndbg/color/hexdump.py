import pwndbg.config as config
import pwndbg.color.theme as theme
from pwndbg.color import generateColorFunction

config_normal    = theme.Parameter('color-hexdump-normal', 'normal', 'color for hexdump command (normal bytes)')
config_printable = theme.Parameter('color-hexdump-printable', 'bold', 'color for hexdump command (printable characters)')
config_zero      = theme.Parameter('color-hexdump-zero', 'red', 'color for hexdump command (zero bytes)')
config_special   = theme.Parameter('color-hexdump-special', 'yellow', 'color for hexdump command (special bytes)')
config_offset    = theme.Parameter('color-hexdump-offset', 'green', 'color for hexdump command (offset label)')
config_separator = theme.Parameter('color-hexdump-separator', 'normal', 'color for hexdump command (group separator)')

def normal(x):
    return generateColorFunction(config.color_hexdump_normal)(x)

def printable(x):
    return generateColorFunction(config.color_hexdump_printable)(x)

def zero(x):
    return generateColorFunction(config.color_hexdump_zero)(x)

def special(x):
    return generateColorFunction(config.color_hexdump_special)(x)

def offset(x):
    return generateColorFunction(config.color_hexdump_offset)(x)

def separator(x):
    return generateColorFunction(config.color_hexdump_separator)(x)
