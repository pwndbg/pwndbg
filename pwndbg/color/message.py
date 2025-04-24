from __future__ import annotations

from typing import Callable

import pwndbg.lib.config
from pwndbg import config
from pwndbg.color import generateColorFunction
from pwndbg.color import theme

config_status_on_color = theme.add_color_param(
    "message_status_on_color", "GREEN", "color of on status messages"
)
config_status_off_color = theme.add_color_param(
    "message_status_off_color", "RED", "color of off status messages"
)

config_notice_color = theme.add_color_param(
    "message_notice_color", "PURPLE", "color of notice messages"
)
config_hint_color = theme.add_color_param(
    "message_hint_color", "YELLOW", "color of hint and marker messages"
)
config_success_color = theme.add_color_param(
    "message_success_color", "GREEN", "color of success messages"
)
config_debug_color = theme.add_color_param("message_debug_color", "BLUE", "color of debug messages")
config_info_color = theme.add_color_param("message_info_color", "WHITE", "color of info messages")
config_warning_color = theme.add_color_param(
    "message_warning_color", "YELLOW", "color of warning messages"
)
config_error_color = theme.add_color_param("message_error_color", "RED", "color of error messages")
config_system_color = theme.add_color_param(
    "message_system_color", "LIGHT_RED", "color of system messages"
)

config_exit_color = theme.add_color_param("message_exit_color", "RED", "color of exit messages")
config_breakpoint_color = theme.add_color_param(
    "message_breakpoint_color", "YELLOW", "color of breakpoint messages"
)
config_signal_color = theme.add_color_param(
    "message_signal_color", "BOLD,RED", "color of signal messages"
)

config_prompt_color: pwndbg.lib.config.Parameter = theme.add_color_param(
    "prompt_color", "BOLD,RED", "prompt color"
)
config_prompt_alive_color: pwndbg.lib.config.Parameter = theme.add_color_param(
    "prompt_alive_color", "BOLD,GREEN", "prompt alive color"
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
