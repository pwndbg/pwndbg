#!/usr/bin/env python
# -*- coding: utf-8 -*-

import pwndbg.color.theme as theme
import pwndbg.config as config
from pwndbg.color import generateColorFunction

config_normal    = theme.ColoredParameter('hexdump-normal-color', 'none', 'color for hexdump command (normal bytes)')
config_printable = theme.ColoredParameter('hexdump-printable-color', 'bold', 'color for hexdump command (printable characters)')
config_zero      = theme.ColoredParameter('hexdump-zero-color', 'red', 'color for hexdump command (zero bytes)')
config_special   = theme.ColoredParameter('hexdump-special-color', 'yellow', 'color for hexdump command (special bytes)')
config_offset    = theme.ColoredParameter('hexdump-offset-color', 'none', 'color for hexdump command (offset label)')
config_address   = theme.ColoredParameter('hexdump-address-color', 'none', 'color for hexdump command (address label)')
config_separator = theme.ColoredParameter('hexdump-separator-color', 'none', 'color for hexdump command (group separator)')
config_highlight_group_lsb = theme.Parameter('hexdump-highlight-group-lsb', 'underline',
                                             'highlight LSB of each group. Applies only if hexdump-adjust-group-endianess'
                                             ' actually changes byte order.')

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

def address(x):
    return generateColorFunction(config.hexdump_address_color)(x)

def separator(x):
    return generateColorFunction(config.hexdump_separator_color)(x)

def highlight_group_lsb(x):
    return generateColorFunction(config.hexdump_highlight_group_lsb)(x)
