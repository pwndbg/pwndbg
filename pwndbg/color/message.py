from __future__ import annotations

from typing import Callable

import pwndbg.lib.config
from pwndbg import config
from pwndbg.color import generateColorFunction
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

config_prompt_color: pwndbg.lib.config.Parameter = theme.add_color_param(
    "prompt-color", "bold,red", "prompt color"
)
config_prompt_alive_color: pwndbg.lib.config.Parameter = theme.add_color_param(
    "prompt-alive-color", "bold,green", "prompt alive color"
)


def on(msg: object) -> str:
    return generateColorFunction(config.message_status_on_color)(msg)


def off(msg: object) -> str:
    return generateColorFunction(config.message_status_off_color)(msg)


def notice(msg: object) -> str:
    return generateColorFunction(config.message_notice_color)(msg)


def hint(msg: object) -> str:
    return generateColorFunction(config.message_hint_color)(msg)


def success(msg: object) -> str:
    return generateColorFunction(config.message_success_color)(msg)


def debug(msg: object) -> str:
    return generateColorFunction(config.message_warning_color)(msg)


def info(msg: object) -> str:
    return generateColorFunction(config.message_warning_color)(msg)


def warn(msg: object) -> str:
    return generateColorFunction(config.message_warning_color)(msg)


def error(msg: object) -> str:
    return generateColorFunction(config.message_error_color)(msg)


def system(msg: object) -> str:
    return generateColorFunction(config.message_system_color)(msg)


def exit(msg: object) -> str:
    return generateColorFunction(config.message_exit_color)(msg)


def breakpoint(msg: object) -> str:
    return generateColorFunction(config.message_breakpoint_color)(msg)


def signal(msg: object) -> str:
    return generateColorFunction(config.message_signal_color)(msg)


def prompt(msg: object) -> str:
    return generateColorFunction(config.prompt_color)(msg)


def alive_prompt(msg: object) -> str:
    return generateColorFunction(config.prompt_alive_color)(msg)


def readline_escape(func_message: Callable[[str], str], text: str) -> str:
    # For readline-based applications, non-printable escape codes must be
    # wrapped with special markers (\001 and \002). These markers inform
    # readline to ignore the escape sequences when calculating the prompt's width.
    # Without these markers, the prompt may break when navigating command history
    # with the UP arrow key or for long commands.
    return "\x01" + func_message("\x02" + text + "\x01") + "\x02"
