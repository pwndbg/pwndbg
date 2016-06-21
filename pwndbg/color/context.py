import pwndbg.config as config
import pwndbg.color.theme as theme
from pwndbg.color import generateColorFunction

config_highlight        = theme.Parameter('highlight-color', 'green,bold', 'color added to highlights like source/pc')
config_register         = theme.Parameter('context-register-color', 'bold', 'color for registers label')
config_register_changed = theme.Parameter('context-register-changed-color', 'normal', 'color for registers label (change marker)')
config_flag_set         = theme.Parameter('context-flag-set-color', 'green,bold', 'color for flags register (flag set)')
config_flag_unset       = theme.Parameter('context-flag-unset-color', 'red', 'color for flags register (flag unset)')
config_banner           = theme.Parameter('banner-color', 'blue', 'color for banner line')

def highlight(x):
    return generateColorFunction(config.highlight_color)(x)

def register(x):
    return generateColorFunction(config.context_register_color)(x)

def register_changed(x):
    return generateColorFunction(config.context_register_changed_color)(x)

def flag_set(x):
    return generateColorFunction(config.context_flag_set_color)(x)

def flag_unset(x):
    return generateColorFunction(config.context_flag_unset_color)(x)

def banner(x):
    return generateColorFunction(config.banner_color)(x)
