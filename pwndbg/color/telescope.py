#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import pwndbg.color.theme as theme
import pwndbg.config as config
from pwndbg.color import generateColorFunction

offset_color = theme.ColoredParameter('telescope-offset-color', 'normal', 'color of the telescope command (offset prefix)')
register_color = theme.ColoredParameter('telescope-register-color', 'bold', 'color of the telescope command (register)')
offset_separator_color = theme.ColoredParameter('telescope-offset-separator-color', 'normal', 'color of the telescope command (offset separator)')
offset_delimiter_color = theme.ColoredParameter('telescope-offset-delimiter-color', 'normal', 'color of the telescope command (offset delimiter)')
repeating_marker_color = theme.ColoredParameter('telescope-repeating-marker-color', 'normal', 'color of the telescope command (repeating values marker)')

def offset(x):
    return generateColorFunction(config.telescope_offset_color)(x)

def register(x):
    return generateColorFunction(config.telescope_register_color)(x)

def separator(x):
    return generateColorFunction(config.telescope_offset_separator_color)(x)

def delimiter(x):
    return generateColorFunction(config.telescope_offset_delimiter_color)(x)

def repeating_marker(x):
    return generateColorFunction(config.telescope_repeating_marker_color)(x)
