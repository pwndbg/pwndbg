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
WHITE          = "\x1b[37m"
GREY = GRAY    = "\x1b[90m"
BOLD           = "\x1b[1m"
UNDERLINE      = "\x1b[4m"

pwndbg.config.Parameter('color-stack', 'yellow', 'color for stack memory')
pwndbg.config.Parameter('color-heap', 'blue', 'color for heap memory')
pwndbg.config.Parameter('color-code', 'red', 'color for executable memory')
pwndbg.config.Parameter('color-data', 'purple', 'color for all other writable memory')
pwndbg.config.Parameter('color-rodata', 'normal', 'color for all read only memory')
pwndbg.config.Parameter('color-rwx', 'underline', 'color added to all RWX memory')
pwndbg.config.Parameter('color-highlight', 'green,bold', 'color added to highlights like source/pc')

def normal(x): return colorize(x, NORMAL)
def black(x): return colorize(x, BLACK)
def red(x): return colorize(x, RED)
def green(x): return colorize(x, GREEN)
def yellow(x): return colorize(x, YELLOW)
def blue(x): return colorize(x, BLUE)
def purple(x): return colorize(x, PURPLE)
def cyan(x): return colorize(x, CYAN)
def white(x): return colorize(x, WHITE)
def gray(x): return colorize(x, GRAY)
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
        function = generateColorFunctionInner(function, globals()[color.lower()])
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
