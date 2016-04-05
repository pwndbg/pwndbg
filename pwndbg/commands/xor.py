from __future__ import print_function

import pwndbg.commands
import pwndbg.memory

@pwndbg.commands.OnlyWhenRunning
@pwndbg.commands.Command
def xor(self, address, key, count):
    '''xor(address, key, count)

    XOR ``count`` bytes at ``address`` with the key ``key``.
    '''
    print(address,key,count)