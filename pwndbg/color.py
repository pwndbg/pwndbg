import gdb
import pwndbg.enhance
import pwndbg.vmmap

SOH            = "\x01"
STX            = "\x02"
NORMAL         = SOH + "\x1b[0m" + STX
BLACK          = SOH + "\x1b[30m" + STX
RED            = SOH + "\x1b[31m" + STX
GREEN          = SOH + "\x1b[32m" + STX
YELLOW         = SOH + "\x1b[33m" + STX
BLUE           = SOH + "\x1b[34m" + STX
PURPLE         = SOH + "\x1b[35m" + STX
CYAN           = SOH + "\x1b[36m" + STX
GREY = GRAY    = SOH + "\x1b[90m" + STX
BOLD           = SOH + "\x1b[1m" + STX
UNDERLINE      = SOH + "\x1b[4m" + STX

STACK = YELLOW
HEAP  = BLUE
CODE  = RED
DATA  = PURPLE

def normal(x): return NORMAL + x
def bold(x): return BOLD + x + NORMAL
def red(x): return RED + x + NORMAL
def blue(x): return BLUE + x + NORMAL
def gray(x): return GRAY + x + NORMAL
def green(x): return GREEN + x + NORMAL
def yellow(x): return YELLOW + x + NORMAL
def underline(x): return UNDERLINE + x + NORMAL

def get(address, text = None):
    """
    Returns a colorized string representing the provided address.

    Arguments:
        address(int): Address to look up
        text(str): Optional text to use in place of the address
              in the return value string.
    """
    page = pwndbg.vmmap.find(int(address))

    if page is None:                 color = NORMAL
    elif '[stack' in page.objfile:   color = STACK
    elif '[heap'  in page.objfile:   color = HEAP
    elif page.execute:               color = CODE
    elif page.rw:                    color = DATA
    else:                            color = NORMAL

    if page and page.rwx:
        color = color + UNDERLINE

    if text is None and isinstance(address, (long, int)) and address > 255:
        text = hex(int(address))
    if text is None:
        text = int(address)

    return "%s%s%s" % (color, text, NORMAL)

def legend():
    return 'LEGEND: ' + ' | '.join((
        STACK + 'STACK' + NORMAL,
        HEAP + 'HEAP' + NORMAL,
        CODE + 'CODE' + NORMAL,
        DATA + 'DATA' + NORMAL,
        UNDERLINE + 'RWX' + NORMAL,
        'RODATA'
    ))
