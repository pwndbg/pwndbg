import pwndbg.config
from pwndbg.color import generateColorFunction

config_highlight        = pwndbg.config.Parameter('color-highlight', 'green,bold', 'color added to highlights like source/pc')
config_register         = pwndbg.config.Parameter('color-register', 'bold', 'color for registers label')
config_register_changed = pwndbg.config.Parameter('color-register-changed', 'normal', 'color for registers label (change marker)')
config_flag_set         = pwndbg.config.Parameter('color-flag-set', 'green,bold', 'color for flags register (flag set)')
config_flag_unset       = pwndbg.config.Parameter('color-flag-unset', 'red', 'color for flags register (flag unset)')
config_banner           = pwndbg.config.Parameter('color-banner', 'blue', 'color for banner line')

def highlight(x):
    return generateColorFunction(pwndbg.config.color_highlight)(x)

def register(x):
    return generateColorFunction(pwndbg.config.color_register)(x)

def register_changed(x):
    return generateColorFunction(pwndbg.config.color_register_changed)(x)

def flag_set(x):
    return generateColorFunction(pwndbg.config.color_flag_set)(x)

def flag_unset(x):
    return generateColorFunction(pwndbg.config.color_flag_unset)(x)

def banner(x):
    return generateColorFunction(pwndbg.config.color_banner)(x)
