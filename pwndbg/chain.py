#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import absolute_import
from __future__ import division
from __future__ import print_function
from __future__ import unicode_literals

import gdb

import pwndbg.color.chain as C
import pwndbg.color.memory as M
import pwndbg.color.theme as theme
import pwndbg.enhance
import pwndbg.memory
import pwndbg.symbol
import pwndbg.typeinfo
import pwndbg.vmmap

LIMIT = pwndbg.config.Parameter('dereference-limit', 5, 'max number of pointers to dereference in a chain')

def get(address, limit=LIMIT, offset=0, hard_stop=None, hard_end=0):
    """
    Recursively dereferences an address.

    Arguments:
        address(int): the first address to begin dereferencing
        limit(int): number of valid pointers
        offset(int): offset into the address to get the next pointer
        hard_stop(int): address to stop at
        hard_end: value to append when hard_stop is reached

    Returns:
        A list representing pointers of each ```address``` and reference
    """
    limit = int(limit)+1
    
    result = []
    for i in range(limit):
        # Don't follow cycles, except to stop at the second occurrence.
        if result.count(address) >= 2:
            break

        if hard_stop is not None and address == hard_stop:
            result.append(hard_end)
            break

        result.append(address)
        try:
            address = int(pwndbg.memory.poi(pwndbg.typeinfo.ppvoid, address + offset))
            address &= pwndbg.arch.ptrmask
        except gdb.MemoryError:
            break

    return result


config_arrow_left  = theme.Parameter('chain-arrow-left', '◂—', 'left arrow of chain formatting')
config_arrow_right = theme.Parameter('chain-arrow-right', '—▸', 'right arrow of chain formatting')
config_contiguous  = theme.Parameter('chain-contiguous-marker', '...', 'contiguous marker of chain formatting')

def format(value, limit=LIMIT, code=True, offset=0, hard_stop=None, hard_end=0):
    """
    Recursively dereferences an address into string representation, or convert the list representation
    of address dereferences into string representation.

    Arguments:
        value(int|list): Either the starting address to be sent to get, or the result of get (a list)
        limit(int): Number of valid pointers
        code(bool): Hint that indicates the value may be an instruction
        offset(int): Offset into the address to get the next pointer
        hard_stop(int): Value to stop on
        hard_end: Value to append when hard_stop is reached: null, value of hard stop, a string.

    Returns:
        A string representing pointers of each address and reference
        Strings format: 0x0804a10 —▸ 0x08061000 ◂— 0x41414141
    """
    limit = int(limit)+1

    # Allow results from get function to be passed to format
    if type(value) == list:
        chain = value
    else:
        chain = get(value, limit, offset, hard_stop, hard_end)

    arrow_left  = C.arrow(' %s ' % config_arrow_left)
    arrow_right = C.arrow(' %s ' % config_arrow_right)

    # Enhance the last entry
    # If there are no pointers (e.g. eax = 0x41414141), then enhance
    # the only element there is.
    if len(chain) == 1:
        enhanced = pwndbg.enhance.enhance(chain[-1], code=code)

    # Otherwise, the last element in the chain is the non-pointer value.
    # We want to enhance the last pointer value. If an offset was used
    # chain failed at that offset, so display that offset.
    elif len(chain) < limit:
        enhanced = pwndbg.enhance.enhance(chain[-2] + offset, code=code)

    else:
        enhanced = C.contiguous('%s' % config_contiguous)

    # Colorize the rest
    rest = []
    for link in chain[:-1]:
        symbol = pwndbg.symbol.get(link) or None
        if symbol:
            symbol = '%#x (%s)' % (link, symbol)
        rest.append(M.get(link, symbol))

    if len(chain) == 1:
        return enhanced

    return arrow_right.join(rest) + arrow_left + enhanced
