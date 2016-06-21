import six

import pwndbg.config as config
import pwndbg.color.theme as theme
import pwndbg.vmmap
from pwndbg.color import generateColorFunction, normal

config_stack  = theme.Parameter('color-stack', 'yellow', 'color for stack memory')
config_heap   = theme.Parameter('color-heap', 'blue', 'color for heap memory')
config_code   = theme.Parameter('color-code', 'red', 'color for executable memory')
config_data   = theme.Parameter('color-data', 'purple', 'color for all other writable memory')
config_rodata = theme.Parameter('color-rodata', 'normal', 'color for all read only memory')
config_rwx    = theme.Parameter('color-rwx', 'underline', 'color added to all RWX memory')

def stack(x):
    return generateColorFunction(config.color_stack)(x)

def heap(x):
    return generateColorFunction(config.color_heap)(x)

def code(x):
    return generateColorFunction(config.color_code)(x)

def data(x):
    return generateColorFunction(config.color_data)(x)

def rodata(x):
    return generateColorFunction(config.color_rodata)(x)

def rwx(x):
    return generateColorFunction(config.color_rwx)(x)

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
