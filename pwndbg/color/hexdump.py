#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

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
