# This hook is necessary for compatibility with Python2.7 versions of GDB
# since they cannot directly cast to integer a gdb.Value object that is
# not already an integer type.
import __builtin__
import gdb
import pwndbg.typeinfo

_int = __builtin__.int

# We need this class to get isinstance(7, xint) to return True
class IsAnInt(type):
    def __instancecheck__(self, other):
        return isinstance(other, _int)

class xint(__builtin__.int):
    __metaclass__ = IsAnInt
    def __new__(cls, value, *a, **kw):
        if isinstance(value, gdb.Value):
            if pwndbg.typeinfo.is_pointer(value):
                value = value.cast(pwndbg.typeinfo.ulong)
            else:
                value = value.cast(pwndbg.typeinfo.long)
        return _int(_int(value, *a, **kw))

__builtin__.int = xint
globals()['int'] = xint

# Additionally, we need to compensate for Python2
if 'long' in globals():
    __builtin__.long = xint
    globals()['long'] = xint