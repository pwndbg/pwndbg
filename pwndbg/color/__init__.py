from __future__ import annotations

import os
import re
from typing import Callable
from typing import Dict
from typing import List
from typing import NamedTuple

from pwndbg.lib.config import Parameter

from . import theme

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


# We assign `none` instead of creating a function since it is faster this way
# While this is a microptimization, the `none` may be called thousands of times with
# a single context or a `hexdump $rsp 5000` call
# A simple benchmark below:
#   In [1]: def f(x): return str(x)
#   In [2]: %timeit f('')
#   117 ns ± 0.642 ns per loop (mean ± std. dev. of 7 runs, 10000000 loops each)
#   In [3]: %timeit str('')
#   72 ns ± 0.222 ns per loop (mean ± std. dev. of 7 runs, 10000000 loops each)
none = str


def normal(x: str) -> str:
    return colorize(x, NORMAL)


def black(x: str) -> str:
    return colorize(x, BLACK)


def red(x: str) -> str:
    return colorize(x, RED)


def green(x: str) -> str:
    return colorize(x, GREEN)


def yellow(x: str) -> str:
    return colorize(x, YELLOW)


def blue(x: str) -> str:
    return colorize(x, BLUE)


def purple(x: str) -> str:
    return colorize(x, PURPLE)


def cyan(x: str) -> str:
    return colorize(x, CYAN)


def light_gray(x: str) -> str:
    return colorize(x, LIGHT_GRAY)


def foreground(x: str) -> str:
    return colorize(x, FOREGROUND)


def gray(x: str) -> str:
    return colorize(x, GRAY)


def light_red(x: str) -> str:
    return colorize(x, LIGHT_RED)


def light_green(x: str) -> str:
    return colorize(x, LIGHT_GREEN)


def light_yellow(x: str) -> str:
    return colorize(x, LIGHT_YELLOW)


def light_blue(x: str) -> str:
    return colorize(x, LIGHT_BLUE)


def light_purple(x: str) -> str:
    return colorize(x, LIGHT_PURPLE)


def light_cyan(x: str) -> str:
    return colorize(x, LIGHT_CYAN)


def white(x: str) -> str:
    return colorize(x, WHITE)


def bold(x: str) -> str:
    return colorize(x, BOLD)


def underline(x: str) -> str:
    return colorize(x, UNDERLINE)


def colorize(x: str, color: str) -> str:
    return color + terminateWith(str(x), color) + NORMAL


# Taken from https://stackoverflow.com/a/14693789
ansi_escape_8bit = re.compile(
    r"(?:\x1B[@-Z\\-_]|[\x80-\x9A\x9C-\x9F]|(?:\x1B\[|\x9B)[0-?]*[ -/]*[@-~])"
)


def unstylize(x: str) -> str:
    return ansi_escape_8bit.sub("", x)


disable_colors = theme.add_param(
    "disable-colors",
    bool(os.environ.get("PWNDBG_DISABLE_COLORS")),
    "whether to color the output or not",
)


def generateColorFunctionInner(
    old: Callable[[object], str], new: Callable[[str], str]
) -> Callable[[object], str]:
    def wrapper(text: object) -> str:
        return new(old(text))

    return wrapper


class ColorParamSpec(NamedTuple):
    name: str
    default: str
    doc: str


class ColorConfig:
    def __init__(self, namespace: str, params: List[ColorParamSpec]) -> None:
        self._namespace = namespace
        self._params: Dict[str, Parameter] = {}
        for param in params:
            self._params[param.name] = theme.add_color_param(
                f"{self._namespace}-{param.name}-color", param.default, param.doc
            )

    def __getattr__(self, attr: str) -> Callable[[str], str]:
        param_name = attr.replace("_", "-")
        if param_name in self._params:
            return generateColorFunction(self._params[param_name])

        raise AttributeError(f"ColorConfig object for {self._namespace} has no attribute '{attr}'")


def generateColorFunction(
    config: str | Parameter, _globals: Dict[str, Callable[[str], str]] = globals()
) -> Callable[[object], str]:
    # the `config` here may be a config Parameter object
    # and if we run with disable_colors or if the config value
    # is empty, we need to ensure we cast it to string
    # so it can be properly formatted e.g. with:
    # "{config_param:5}".format(config_param=some_config_parameter)
    function = str

    if disable_colors:
        return function

    for color in config.split(","):
        func_name = color.lower().replace("-", "_")
        function = generateColorFunctionInner(function, _globals[func_name])
    return function


def strip(x: str) -> str:
    return re.sub("\x1b\\[[\\d;]+m", "", x)


def terminateWith(x: str, color: str) -> str:
    return x.replace("\x1b[0m", NORMAL + color)


def ljust_colored(x: str, length: int, char: str = " ") -> str:
    remaining = length - len(strip(x))
    return x + ((remaining // len(char) + 1) * char)[:remaining]


def rjust_colored(x: str, length: int, char: str = " "):
    remaining = length - len(strip(x))
    return ((remaining // len(char) + 1) * char)[:remaining] + x
