import gdb
import sys
from types import ModuleType

import gef.memoize

class module(ModuleType):
    @property
    def pid(self):
        i = gdb.selected_inferior()
        if i is not None:
            return i.pid
        return 0

    @property
    def alive(self):
        return self.pid > 0

# To prevent garbage collection
tether = sys.modules[__name__]

sys.modules[__name__] = module(__name__, '')