from __future__ import annotations

from pwndbg.color import theme

config_integer_color = theme.add_color_param(
    "enhance-integer-value-color", "none", "color of value enhance (integer)"
)
config_string_color = theme.add_color_param(
    "enhance-string-value-color", "none", "color of value enhance (string)"
)
config_comment_color = theme.add_color_param(
    "enhance-comment-color", "none", "color of value enhance (comment)"
)
config_unknown_color = theme.add_color_param(
    "enhance-unknown-color", "none", "color of value enhance (unknown value)"
)


def integer(x):
    return config_integer_color.color_function(x)


def string(x):
    return config_string_color.color_function(x)


def comment(x):
    return config_comment_color.color_function(x)


def unknown(x):
    return config_unknown_color.color_function(x)
