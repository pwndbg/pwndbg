#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import pwndbg.color.theme as theme
import pwndbg.config as config
from pwndbg.color import generateColorFunction

config_prefix         = theme.Parameter('backtrace-prefix', '►', 'prefix for current backtrace label')
config_prefix_color   = theme.ColoredParameter('backtrace-prefix-color', 'none', 'color for prefix of current backtrace label')
config_address_color  = theme.ColoredParameter('backtrace-address-color', 'none', 'color for backtrace (address)')
config_symbol_color   = theme.ColoredParameter('backtrace-symbol-color', 'none', 'color for backtrace (symbol)')
config_label_color    = theme.ColoredParameter('backtrace-frame-label-color', 'none', 'color for backtrace (frame label)')

def prefix(x):
    return generateColorFunction(config.backtrace_prefix_color)(x)

def address(x):
    return generateColorFunction(config.backtrace_address_color)(x)

def symbol(x):
    return generateColorFunction(config.backtrace_symbol_color)(x)

def frame_label(x):
    return generateColorFunction(config.backtrace_frame_label_color)(x)
