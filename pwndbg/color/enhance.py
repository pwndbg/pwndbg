import pwndbg.config as config
import pwndbg.color.theme as theme
from pwndbg.color import generateColorFunction

config_integer_color = theme.Parameter('enhance-integer-value-color', 'none', 'color of value enhance (integer)')
config_string_color  = theme.Parameter('enhance-string-value-color', 'none', 'color of value enhance (string)')
config_comment_color = theme.Parameter('enhance-comment-color', 'none', 'color of value enhance (comment)')
config_unknown_color = theme.Parameter('enhance-unknown-color', 'none', 'color of value enhance (unknown value)')

def integer(x):
    return generateColorFunction(config.enhance_integer_value_color)(x)

def string(x):
    return generateColorFunction(config.enhance_string_value_color)(x)

def comment(x):
    return generateColorFunction(config.enhance_comment_color)(x)

def unknown(x):
    return generateColorFunction(config.enhance_unknown_color)(x)
