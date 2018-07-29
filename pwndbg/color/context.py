#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import pwndbg.color.theme as theme
import pwndbg.config as config
from pwndbg.color import generateColorFunction

config_prefix_color             = theme.ColoredParameter('code-prefix-color', 'none', "color for 'context code' command (prefix marker)")
config_highlight_color          = theme.ColoredParameter('highlight-color', 'green,bold', 'color added to highlights like source/pc')
config_register_color           = theme.ColoredParameter('context-register-color', 'bold', 'color for registers label')
config_flag_value_color         = theme.ColoredParameter('context-flag-value-color', 'none', 'color for flags register (register value)')
config_flag_bracket_color       = theme.ColoredParameter('context-flag-bracket-color', 'none', 'color for flags register (bracket)')
config_flag_set_color           = theme.ColoredParameter('context-flag-set-color', 'green,bold', 'color for flags register (flag set)')
config_flag_unset_color         = theme.ColoredParameter('context-flag-unset-color', 'red', 'color for flags register (flag unset)')
config_flag_changed_color       = theme.ColoredParameter('context-flag-changed-color', 'underline', 'color for flags register (flag changed)')
config_banner_color             = theme.ColoredParameter('banner-color', 'blue', 'color for banner line')
config_banner_title             = theme.ColoredParameter('banner-title-color', 'none', 'color for banner title')
config_register_changed_color   = theme.ColoredParameter('context-register-changed-color', 'normal', 'color for registers label (change marker)')
config_register_changed_marker  = theme.Parameter('context-register-changed-marker', '*', 'change marker for registers label')

def prefix(x):
    return generateColorFunction(config.code_prefix_color)(x)

def highlight(x):
    return generateColorFunction(config.highlight_color)(x)

def register(x):
    return generateColorFunction(config.context_register_color)(x)

def register_changed(x):
    return generateColorFunction(config.context_register_changed_color)(x)

def flag_bracket(x):
    return generateColorFunction(config.context_flag_bracket_color)(x)

def flag_value(x):
    return generateColorFunction(config.context_flag_value_color)(x)

def flag_set(x):
    return generateColorFunction(config.context_flag_set_color)(x)

def flag_unset(x):
    return generateColorFunction(config.context_flag_unset_color)(x)

def flag_changed(x):
    return generateColorFunction(config.context_flag_changed_color)(x)

def banner(x):
    return generateColorFunction(config.banner_color)(x)

def banner_title(x):
    return generateColorFunction(config.banner_title_color)(x)
