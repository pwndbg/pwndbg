import pwndbg.config as config
import pwndbg.color.theme as theme
from pwndbg.color import generateColorFunction

config_normal    = theme.Parameter('hexdump-normal-color', 'normal', 'color for hexdump command (normal bytes)')
config_printable = theme.Parameter('hexdump-printable-color', 'bold', 'color for hexdump command (printable characters)')
config_zero      = theme.Parameter('hexdump-zero-color', 'red', 'color for hexdump command (zero bytes)')
config_special   = theme.Parameter('hexdump-special-color', 'yellow', 'color for hexdump command (special bytes)')
config_offset    = theme.Parameter('hexdump-offset-color', 'green', 'color for hexdump command (offset label)')
config_separator = theme.Parameter('hexdump-separator-color', 'normal', 'color for hexdump command (group separator)')

def normal(x):
    return generateColorFunction(config.hexdump_normal_color)(x)

def printable(x):
    return generateColorFunction(config.hexdump_printable_color)(x)

def zero(x):
    return generateColorFunction(config.hexdump_zero_color)(x)

def special(x):
    return generateColorFunction(config.hexdump_special_color)(x)

def offset(x):
    return generateColorFunction(config.hexdump_offset_color)(x)

def separator(x):
    return generateColorFunction(config.hexdump_separator_color)(x)
