import gdb
import gef.vmmap

NORMAL         = "\x1b[0m"
BLACK          = "\x1b[30m"
RED            = "\x1b[31m"
GREEN          = "\x1b[32m"
YELLOW         = "\x1b[33m"
BLUE           = "\x1b[34m"
PURPLE         = "\x1b[35m"
CYAN           = "\x1b[36m"
GREY = GRAY    = "\x1b[37m"
BOLD           = "\x1b[1m"
UNDERLINE      = "\x1b[4m"

STACK = BLUE
HEAP  = BLUE + BOLD
CODE  = RED
RWX   = RED  + BOLD
DATA  = YELLOW

def get(address, text = None):
    """
    Returns a colorized string representing the provided address.

    Arguments:
        address(int): Address to look up
        text(str): Optional text to use in place of the address
              in the return value string.
    """
    page = gef.vmmap.find(int(address))

    if page is None:                 color = NORMAL
    elif '[stack' in page.objfile:   color = STACK
    elif '[heap'  in page.objfile:   color = HEAP
    elif page.rwx:                   color = RWX
    elif page.execute:               color = CODE
    elif page.rw:                    color = DATA
    else:                            color = NORMAL

    if text is None and isinstance(address, int) and address > 255:
        text = hex(address)
    if text is None:
        text = address

    return "%s%s%s" % (color, text, NORMAL)
