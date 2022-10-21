import os
import re
from typing import Any

import pwndbg.lib.memoize

from . import theme as theme

NORMAL = "\x1b[0m"
BLACK = "\x1b[30m"
RED = "\x1b[31m"
GREEN = "\x1b[32m"
YELLOW = "\x1b[33m"
BLUE = "\x1b[34m"
PURPLE = "\x1b[35m"
CYAN = "\x1b[36m"
LIGHT_GREY = LIGHT_GRAY = "\x1b[37m"
FOREGROUND = "\x1b[39m"
GREY = GRAY = "\x1b[90m"
LIGHT_RED = "\x1b[91m"
LIGHT_GREEN = "\x1b[92m"
LIGHT_YELLOW = "\x1b[93m"
LIGHT_BLUE = "\x1b[94m"
LIGHT_PURPLE = "\x1b[95m"
LIGHT_CYAN = "\x1b[96m"
WHITE = "\x1b[97m"
BOLD = "\x1b[1m"
UNDERLINE = "\x1b[4m"


def none(x):
    return str(x)


def normal(x):
    return colorize(x, NORMAL)


def black(x):
    return colorize(x, BLACK)


def red(x):
    return colorize(x, RED)


def green(x):
    return colorize(x, GREEN)


def yellow(x):
    return colorize(x, YELLOW)


def blue(x):
    return colorize(x, BLUE)


def purple(x):
    return colorize(x, PURPLE)


def cyan(x):
    return colorize(x, CYAN)


def light_gray(x):
    return colorize(x, LIGHT_GRAY)


def foreground(x):
    return colorize(x, FOREGROUND)


def gray(x):
    return colorize(x, GRAY)


def light_red(x):
    return colorize(x, LIGHT_RED)


def light_green(x):
    return colorize(x, LIGHT_GREEN)


def light_yellow(x):
    return colorize(x, LIGHT_YELLOW)


def light_blue(x):
    return colorize(x, LIGHT_BLUE)


def light_purple(x):
    return colorize(x, LIGHT_PURPLE)


def light_cyan(x):
    return colorize(x, LIGHT_CYAN)


def white(x):
    return colorize(x, WHITE)


def bold(x):
    return colorize(x, BOLD)


def underline(x):
    return colorize(x, UNDERLINE)


def colorize(x, color):
    return color + terminateWith(str(x), color) + NORMAL


disable_colors = theme.add_param(
    "disable-colors",
    bool(os.environ.get("PWNDBG_DISABLE_COLORS")),
    "whether to color the output or not",
)


@pwndbg.lib.memoize.reset_on_stop
def generateColorFunctionInner(old, new):
    def wrapper(text):
        return new(old(text))

    return wrapper


class ColorConfig:
    def __init__(self, namespace):
        self.namespace = namespace
        self.params = {}

    def add_color_param(self, name: str, default: Any, doc: str):
        self.params[name] = theme.add_color_param(f"{self.namespace}-{name}-color", default, doc)

    def __getattr__(self, attr):
        param_name = attr.replace("_", "-")
        if param_name in self.params:
            return generateColorFunction(self.params[param_name])

        raise AttributeError


def generateColorFunction(config: str):
    # the `x` here may be a config Parameter object
    # and if we run with disable_colors or if the config value
    # is empty, we need to ensure we cast it to string
    # so it can be properly formatted e.g. with:
    # "{config_param:5}".format(config_param=some_config_parameter)
    function = lambda x: str(x)

    if disable_colors:
        return function

    for color in config.split(","):
        func_name = color.lower().replace("-", "_")
        function = generateColorFunctionInner(function, globals()[func_name])
    return function


def strip(x):
    return re.sub("\x1b\\[[\\d;]+m", "", x)


def terminateWith(x, color):
    return re.sub("\x1b\\[0m", NORMAL + color, x)


def ljust_colored(x, length, char=" "):
    remaining = length - len(strip(x))
    return x + ((remaining // len(char) + 1) * char)[:remaining]


def rjust_colored(x, length, char=" "):
    remaining = length - len(strip(x))
    return ((remaining // len(char) + 1) * char)[:remaining] + x
