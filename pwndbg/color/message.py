from pwndbg.color import generateColorFunction
from pwndbg.color import theme
from pwndbg.gdblib import config

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


def on(msg):
    return generateColorFunction(config.message_status_on_color)(msg)


def off(msg):
    return generateColorFunction(config.message_status_off_color)(msg)


def notice(msg):
    return generateColorFunction(config.message_notice_color)(msg)


def hint(msg):
    return generateColorFunction(config.message_hint_color)(msg)


def success(msg):
    return generateColorFunction(config.message_success_color)(msg)


def warn(msg):
    return generateColorFunction(config.message_warning_color)(msg)


def error(msg):
    return generateColorFunction(config.message_error_color)(msg)


def system(msg):
    return generateColorFunction(config.message_system_color)(msg)


def exit(msg):
    return generateColorFunction(config.message_exit_color)(msg)


def breakpoint(msg):
    return generateColorFunction(config.message_breakpoint_color)(msg)


def signal(msg):
    return generateColorFunction(config.message_signal_color)(msg)


def prompt(msg):
    return generateColorFunction(config.prompt_color)(msg)
