# This hook is necessary for compatibility with Python2.7 versions of GDB
# since they cannot directly cast to integer a gdb.Value object that is
# not already an integer type.
import gdb
import sys
import pwndbg.typeinfo

if sys.version_info < (3,0):
    import __builtin__ as builtins
    _int = builtins.int

    # We need this class to get isinstance(7, xint) to return True
    class IsAnInt(type):
        def __instancecheck__(self, other):
            return isinstance(other, _int)

    class xint(builtins.int):
        __metaclass__ = IsAnInt
        def __new__(cls, value, *a, **kw):
            if isinstance(value, gdb.Value):
                if pwndbg.typeinfo.is_pointer(value):
                    value = value.cast(pwndbg.typeinfo.ulong)
                else:
                    value = value.cast(pwndbg.typeinfo.long)
            return _int(_int(value, *a, **kw))

    builtins.int = xint
    globals()['int'] = xint

    # Additionally, we need to compensate for Python2
else:
    import builtins
    builtins.long = int
    globals()['long'] = int
