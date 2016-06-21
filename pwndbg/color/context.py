import pwndbg.config as config
import pwndbg.color.theme as theme
from pwndbg.color import generateColorFunction

config_highlight        = theme.Parameter('color-highlight', 'green,bold', 'color added to highlights like source/pc')
config_register         = theme.Parameter('color-register', 'bold', 'color for registers label')
config_register_changed = theme.Parameter('color-register-changed', 'normal', 'color for registers label (change marker)')
config_flag_set         = theme.Parameter('color-flag-set', 'green,bold', 'color for flags register (flag set)')
config_flag_unset       = theme.Parameter('color-flag-unset', 'red', 'color for flags register (flag unset)')
config_banner           = theme.Parameter('color-banner', 'blue', 'color for banner line')

def highlight(x):
    return generateColorFunction(config.color_highlight)(x)

def register(x):
    return generateColorFunction(config.color_register)(x)

def register_changed(x):
    return generateColorFunction(config.color_register_changed)(x)

def flag_set(x):
    return generateColorFunction(config.color_flag_set)(x)

def flag_unset(x):
    return generateColorFunction(config.color_flag_unset)(x)

def banner(x):
    return generateColorFunction(config.color_banner)(x)
