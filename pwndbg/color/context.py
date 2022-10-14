import pwndbg.color.theme as theme
from pwndbg.color import generateColorFunction
from pwndbg.gdblib import config

config_prefix_color = theme.add_color_param(
    "code-prefix-color", "none", "color for 'context code' command (prefix marker)"
)
config_highlight_color = theme.add_color_param(
    "highlight-color", "green,bold", "color added to highlights like source/pc"
)
config_register_color = theme.add_color_param(
    "context-register-color", "bold", "color for registers label"
)
config_flag_value_color = theme.add_color_param(
    "context-flag-value-color", "none", "color for flags register (register value)"
)
config_flag_bracket_color = theme.add_color_param(
    "context-flag-bracket-color", "none", "color for flags register (bracket)"
)
config_flag_set_color = theme.add_color_param(
    "context-flag-set-color", "green,bold", "color for flags register (flag set)"
)
config_flag_unset_color = theme.add_color_param(
    "context-flag-unset-color", "red", "color for flags register (flag unset)"
)
config_flag_changed_color = theme.add_color_param(
    "context-flag-changed-color", "underline", "color for flags register (flag changed)"
)
config_banner_color = theme.add_color_param("banner-color", "blue", "color for banner line")
config_banner_title = theme.add_color_param("banner-title-color", "none", "color for banner title")
config_register_changed_color = theme.add_color_param(
    "context-register-changed-color", "red", "color for registers label (change marker)"
)
config_register_changed_marker = theme.add_param(
    "context-register-changed-marker", "*", "change marker for registers label"
)
config_comment = theme.add_color_param("comment-color", "gray", "color for comment")


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


def comment(x):
    return generateColorFunction(config.comment_color)(x)


def format_flags(value, flags, last=None):
    desc = flag_value("%#x" % value)
    if not flags:
        return desc

    names = []
    for name, bit in flags.items():
        bit = 1 << bit
        if value & bit:
            name = name.upper()
            name = flag_set(name)
        else:
            name = name.lower()
            name = flag_unset(name)

        if last is not None and value & bit != last & bit:
            name = flag_changed(name)
        names.append(name)

    return "%s %s %s %s" % (desc, flag_bracket("["), " ".join(names), flag_bracket("]"))
