import pwndbg.config as config
import pwndbg.color.theme as theme
from pwndbg.color import generateColorFunction

telescope_offset_color = theme.Parameter('telescope-offset-color', 'normal', 'color of the telescope command (offset prefix)')
telescope_register_color = theme.Parameter('telescope-register-color', 'bold', 'color of the telescope command (register)')

def offset(x):
    return generateColorFunction(config.telescope_offset_color)(x)

def register(x):
    return generateColorFunction(config.telescope_register_color)(x)
