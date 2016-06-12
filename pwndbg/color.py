from __future__ import print_function
import functools
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
GREY = GRAY    = "\x1b[90m"
BOLD           = "\x1b[1m"
UNDERLINE      = "\x1b[4m"

pwndbg.config.Parameter('color-stack', 'yellow', 'color for stack memory')
pwndbg.config.Parameter('color-heap', 'blue', 'color for heap memory')
pwndbg.config.Parameter('color-code', 'red', 'color for executable memory')
pwndbg.config.Parameter('color-data', 'purple', 'color for all other writable memory')
pwndbg.config.Parameter('color-rodata', 'normal', 'color for all other writable memory')
pwndbg.config.Parameter('color-rwx', 'underline', 'color added to all RWX memory')

def normal(x): return NORMAL + str(x)
def bold(x): return BOLD + str(x) + NORMAL
def red(x): return RED + str(x) + NORMAL
def blue(x): return BLUE + str(x) + NORMAL
def gray(x): return GRAY + str(x) + NORMAL
def green(x): return GREEN + str(x) + NORMAL
def cyan(x): return CYAN + str(x) + NORMAL
def yellow(x): return YELLOW + str(x) + NORMAL
def purple(x): return PURPLE + str(x) + NORMAL
def underline(x): return UNDERLINE + str(x) + NORMAL

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

    if text is None and isinstance(address, (long, int)) and address > 255:
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
