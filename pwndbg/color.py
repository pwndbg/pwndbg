from __future__ import print_function
from __future__ import unicode_literals

import functools
import re

import six

import gdb
import pwndbg.config
import pwndbg.enhance
import pwndbg.memoize
import pwndbg.vmmap

NORMAL         = "\x1b[0m"
BLACK          = "\x1b[30m"
RED            = "\x1b[31m"
GREEN          = "\x1b[32m"
YELLOW         = "\x1b[33m"
BLUE           = "\x1b[34m"
PURPLE         = "\x1b[35m"
CYAN           = "\x1b[36m"
LIGHT_GREY = LIGHT_GRAY = "\x1b[37m"
FOREGROUND     = "\x1b[39m"
GREY = GRAY    = "\x1b[90m"
LIGHT_RED      = "\x1b[91m"
LIGHT_GREEN    = "\x1b[92m"
LIGHT_YELLOW   = "\x1b[93m"
LIGHT_BLUE     = "\x1b[94m"
LIGHT_PURPLE   = "\x1b[95m"
LIGHT_CYAN     = "\x1b[96m"
WHITE          = "\x1b[97m"
BOLD           = "\x1b[1m"
UNDERLINE      = "\x1b[4m"

pwndbg.config.Parameter('color-stack', 'yellow', 'color for stack memory')
pwndbg.config.Parameter('color-heap', 'blue', 'color for heap memory')
pwndbg.config.Parameter('color-code', 'red', 'color for executable memory')
pwndbg.config.Parameter('color-data', 'purple', 'color for all other writable memory')
pwndbg.config.Parameter('color-rodata', 'normal', 'color for all read only memory')
pwndbg.config.Parameter('color-rwx', 'underline', 'color added to all RWX memory')
pwndbg.config.Parameter('color-highlight', 'green,bold', 'color added to highlights like source/pc')
pwndbg.config.Parameter('color-register', 'bold', 'color for registers label')
pwndbg.config.Parameter('color-register-changed', 'normal', 'color for registers label (change marker)')
pwndbg.config.Parameter('color-flag-set', 'green,bold', 'color for flags register (flag set)')
pwndbg.config.Parameter('color-flag-unset', 'red', 'color for flags register (flag unset)')
pwndbg.config.Parameter('color-banner', 'blue', 'color for banner line')
pwndbg.config.Parameter('color-nearpc-symbol', 'normal', 'color for nearpc command (symbol)')
pwndbg.config.Parameter('color-nearpc-address', 'normal', 'color for nearpc command (address)')
pwndbg.config.Parameter('color-nearpc-prefix', 'red,bold', 'color for nearpc command (prefix marker)')
pwndbg.config.Parameter('color-nearpc-syscall', 'red', 'color for nearpc command (syscall name)')
pwndbg.config.Parameter('color-nearpc-argument', 'bold', 'color for nearpc command (target argument)')
pwndbg.config.Parameter('color-disasm-branch', 'bold', 'color for disasm (branch/call instruction)')
pwndbg.config.Parameter('color-hexdump-normal', 'normal', 'color for hexdump command (normal bytes)')
pwndbg.config.Parameter('color-hexdump-printable', 'bold', 'color for hexdump command (printable characters)')
pwndbg.config.Parameter('color-hexdump-zero', 'red', 'color for hexdump command (zero bytes)')
pwndbg.config.Parameter('color-hexdump-special', 'yellow', 'color for hexdump command (special bytes)')
pwndbg.config.Parameter('color-hexdump-offset', 'green', 'color for hexdump command (offset label)')
pwndbg.config.Parameter('color-hexdump-separator', 'normal', 'color for hexdump command (group separator)')

def none(x): return str(x)
def normal(x): return colorize(x, NORMAL)
def black(x): return colorize(x, BLACK)
def red(x): return colorize(x, RED)
def green(x): return colorize(x, GREEN)
def yellow(x): return colorize(x, YELLOW)
def blue(x): return colorize(x, BLUE)
def purple(x): return colorize(x, PURPLE)
def cyan(x): return colorize(x, CYAN)
def light_gray(x): return colorize(x, LIGHT_GRAY)
def foreground(x): return colorize(x, FOREGROUND)
def gray(x): return colorize(x, GRAY)
def light_red(x): return colorize(x, LIGHT_RED)
def light_green(x): return colorize(x, LIGHT_GREEN)
def light_yellow(x): return colorize(x, LIGHT_YELLOW)
def light_blue(x): return colorize(x, LIGHT_BLUE)
def light_purple(x): return colorize(x, LIGHT_PURPLE)
def light_cyan(x): return colorize(x, LIGHT_CYAN)
def white(x): return colorize(x, WHITE)
def bold(x): return colorize(x, BOLD)
def underline(x): return colorize(x, UNDERLINE)
def colorize(x, color): return color + terminateWith(str(x), color) + NORMAL

@pwndbg.memoize.reset_on_stop
def generateColorFunctionInner(old, new):
    def wrapper(text):
        return new(old(text))
    return wrapper

def generateColorFunction(config):
    function = lambda x: x
    for color in str(config).split(','):
        function = generateColorFunctionInner(function, globals()[color.lower().replace('-', '_')])
    return function

def stack(x):
    return generateColorFunction(pwndbg.config.color_stack)(x)

def heap(x):
    return generateColorFunction(pwndbg.config.color_heap)(x)

def code(x):
    return generateColorFunction(pwndbg.config.color_code)(x)

def data(x):
    return generateColorFunction(pwndbg.config.color_data)(x)

def rodata(x):
    return generateColorFunction(pwndbg.config.color_rodata)(x)

def rwx(x):
    return generateColorFunction(pwndbg.config.color_rwx)(x)

def highlight(x):
    return generateColorFunction(pwndbg.config.color_highlight)(x)

def register(x):
    return generateColorFunction(pwndbg.config.color_register)(x)

def register_changed(x):
    return generateColorFunction(pwndbg.config.color_register_changed)(x)

def flag_set(x):
    return generateColorFunction(pwndbg.config.color_flag_set)(x)

def flag_unset(x):
    return generateColorFunction(pwndbg.config.color_flag_unset)(x)

def banner(x):
    return generateColorFunction(pwndbg.config.color_banner)(x)

def nearpc_symbol(x):
    return generateColorFunction(pwndbg.config.color_nearpc_symbol)(x)

def nearpc_address(x):
    return generateColorFunction(pwndbg.config.color_nearpc_address)(x)

def nearpc_prefix(x):
    return generateColorFunction(pwndbg.config.color_nearpc_prefix)(x)

def nearpc_syscall(x):
    return generateColorFunction(pwndbg.config.color_nearpc_syscall)(x)

def nearpc_argument(x):
    return generateColorFunction(pwndbg.config.color_nearpc_argument)(x)

def disasm_branch(x):
    return generateColorFunction(pwndbg.config.color_disasm_branch)(x)

def hexdump_normal(x):
    return generateColorFunction(pwndbg.config.color_hexdump_normal)(x)

def hexdump_printable(x):
    return generateColorFunction(pwndbg.config.color_hexdump_printable)(x)

def hexdump_zero(x):
    return generateColorFunction(pwndbg.config.color_hexdump_zero)(x)

def hexdump_special(x):
    return generateColorFunction(pwndbg.config.color_hexdump_special)(x)

def hexdump_offset(x):
    return generateColorFunction(pwndbg.config.color_hexdump_offset)(x)

def hexdump_separator(x):
    return generateColorFunction(pwndbg.config.color_hexdump_separator)(x)

def get(address, text = None):
    """
    Returns a colorized string representing the provided address.

    Arguments:
        address(int): Address to look up
        text(str): Optional text to use in place of the address
              in the return value string.
    """
    address = int(address)

    page = pwndbg.vmmap.find(int(address))

    if page is None:                 color = normal
    elif '[stack' in page.objfile:   color = stack
    elif '[heap'  in page.objfile:   color = heap
    elif page.execute:               color = code
    elif page.rw:                    color = data
    else:                            color = rodata

    if page and page.rwx:
        old_color = color
        color = lambda x: rwx(old_color(x))

    if text is None and isinstance(address, six.integer_types) and address > 255:
        text = hex(int(address))
    if text is None:
        text = str(int(address))

    return color(text)

def legend():
    return 'LEGEND: ' + ' | '.join((
        stack('STACK'),
        heap('HEAP'),
        code('CODE'),
        data('DATA'),
        rwx('RWX'),
        rodata('RODATA')
    ))

def strip(x):
    return re.sub('\x1b\\[\d+m', '', x)

def terminateWith(x, color):
    return re.sub('\x1b\\[0m', NORMAL + color, x)
