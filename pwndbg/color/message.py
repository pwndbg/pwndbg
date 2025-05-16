from __future__ import annotations

from typing import Callable

from pwndbg.color import theme

config_status_on_color = theme.add_color_param(
    "message-status-on-color", "green", "color of on status messages"
)
config_status_off_color = theme.add_color_param(
    "message-status-off-color", "red", "color of off status messages"
)

config_notice_color = theme.add_color_param(
    "message-notice-color", "purple", "color of notice messages"
)
config_hint_color = theme.add_color_param(
    "message-hint-color", "yellow", "color of hint and marker messages"
)
config_success_color = theme.add_color_param(
    "message-success-color", "green", "color of success messages"
)
config_debug_color = theme.add_color_param("message-debug-color", "blue", "color of debug messages")
config_info_color = theme.add_color_param("message-info-color", "white", "color of info messages")
config_warning_color = theme.add_color_param(
    "message-warning-color", "yellow", "color of warning messages"
)
config_error_color = theme.add_color_param("message-error-color", "red", "color of error messages")
config_system_color = theme.add_color_param(
    "message-system-color", "light-red", "color of system messages"
)

config_exit_color = theme.add_color_param("message-exit-color", "red", "color of exit messages")
config_breakpoint_color = theme.add_color_param(
    "message-breakpoint-color", "yellow", "color of breakpoint messages"
)
config_signal_color = theme.add_color_param(
    "message-signal-color", "bold,red", "color of signal messages"
)

config_prompt_color = theme.add_color_param("prompt-color", "bold,red", "prompt color")
config_prompt_alive_color = theme.add_color_param(
    "prompt-alive-color", "bold,green", "prompt alive color"
)


def on(msg: object) -> str:
    return config_status_on_color.color_function(msg)


def off(msg: object) -> str:
    return config_status_off_color.color_function(msg)


def notice(msg: object) -> str:
    return config_notice_color.color_function(msg)


def hint(msg: object) -> str:
    return config_hint_color.color_function(msg)


def success(msg: object) -> str:
    return config_success_color.color_function(msg)


def debug(msg: object) -> str:
    return config_debug_color.color_function(msg)


def info(msg: object) -> str:
    return config_info_color.color_function(msg)


def warn(msg: object) -> str:
    return config_warning_color.color_function(msg)


def error(msg: object) -> str:
    return config_error_color.color_function(msg)


def system(msg: object) -> str:
    return config_system_color.color_function(msg)


def exit(msg: object) -> str:
    return config_exit_color.color_function(msg)


def breakpoint(msg: object) -> str:
    return config_breakpoint_color.color_function(msg)


def signal(msg: object) -> str:
    return config_signal_color.color_function(msg)


def prompt(msg: object) -> str:
    return config_prompt_color.color_function(msg)


def alive_prompt(msg: object) -> str:
    return config_prompt_alive_color.color_function(msg)


def readline_escape(func_message: Callable[[str], str], text: str) -> str:
    # For readline-based applications, non-printable escape codes must be
    # wrapped with special markers (\001 and \002). These markers inform
    # readline to ignore the escape sequences when calculating the prompt's width.
    # Without these markers, the prompt may break when navigating command history
    # with the UP arrow key or for long commands.
    return "\x01" + func_message("\x02" + text + "\x01") + "\x02"
