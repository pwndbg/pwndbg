from pwndbg.color import ColorConfig
from pwndbg.color import ColorParamSpec
from pwndbg.gdblib import config

# TODO: Should probably change - to .
c = ColorConfig(
    "context",
    [
        ColorParamSpec("register", "bold", "color for registers label"),
        ColorParamSpec("register-changed", "red", "color for registers label (change marker)"),
        ColorParamSpec("flag-value", "none", "color for flags register (register value)"),
        ColorParamSpec("flag-bracket", "none", "color for flags register (bracket)"),
        ColorParamSpec("flag-set", "green,bold", "color for flags register (flag set)"),
        ColorParamSpec("flag-unset", "red", "color for flags register (flag unset)"),
        ColorParamSpec("flag-changed", "underline", "color for flags register (flag changed)"),
        ColorParamSpec("banner", "blue", "color for banner line"),
        ColorParamSpec("banner-title", "none", "color for banner title"),
        ColorParamSpec("code-prefix", "none", "color for 'context code' command (prefix marker)"),
        ColorParamSpec("highlight", "green,bold", "color added to highlights like source/pc"),
        ColorParamSpec("comment", "gray", "color for comment"),
        ColorParamSpec("backtrace-prefix", "none", "color for prefix of current backtrace label"),
        ColorParamSpec("backtrace-address", "none", "color for backtrace (address)"),
        ColorParamSpec("backtrace-symbol", "none", "color for backtrace (symbol)"),
        ColorParamSpec("backtrace-frame-label", "none", "color for backtrace (frame label)"),
    ],
)

# Deprecated 2022-10-23
config.add_deprecated_param("code-prefix-color", "context-code-prefix-color", scope="theme")
config.add_deprecated_param("highlight-color", "context-highlight-color", scope="theme")
config.add_deprecated_param("comment-color", "context-comment-color", scope="theme")
config.add_deprecated_param(
    "backtrace-prefix-color", "context-backtrace-prefix-color", scope="theme"
)
config.add_deprecated_param(
    "backtrace-address-color", "context-backtrace-address-color", scope="theme"
)
config.add_deprecated_param(
    "backtrace-symbol-color", "context-backtrace-symbol-color", scope="theme"
)
config.add_deprecated_param(
    "backtrace-frame-label-color", "context-backtrace-frame-label-color", scope="theme"
)
