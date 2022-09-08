import pwndbg.color.theme as theme
import pwndbg.gdblib.config as config
from pwndbg.color import generateColorFunction

config_prefix = theme.add_param("backtrace-prefix", "►", "prefix for current backtrace label")
config_prefix_color = theme.add_color_param(
    "backtrace-prefix-color", "none", "color for prefix of current backtrace label"
)
config_address_color = theme.add_color_param(
    "backtrace-address-color", "none", "color for backtrace (address)"
)
config_symbol_color = theme.add_color_param(
    "backtrace-symbol-color", "none", "color for backtrace (symbol)"
)
config_label_color = theme.add_color_param(
    "backtrace-frame-label-color", "none", "color for backtrace (frame label)"
)


def prefix(x):
    return generateColorFunction(config.backtrace_prefix_color)(x)


def address(x):
    return generateColorFunction(config.backtrace_address_color)(x)


def symbol(x):
    return generateColorFunction(config.backtrace_symbol_color)(x)


def frame_label(x):
    return generateColorFunction(config.backtrace_frame_label_color)(x)
