#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
Dynamic configuration system for pwndbg, using GDB's built-in Parameter
mechanism.

To create a new pwndbg configuration point, create an instance of
``pwndbg.config.Parameter``.

Parameters should be declared in the module in which they are primarily
used, or in this module for general-purpose parameters.

All pwndbg Parameter types are accessible via property access on this
module, for example:

    >>> pwndbg.config.Parameter('example-value', 7, 'an example')
    >>> int(pwndbg.config.example_value)
    7
"""
import codecs
import collections
import re
import sys
import types
from functools import total_ordering

import gdb

import pwndbg.decorators

TYPES = collections.OrderedDict()

# The value is a plain boolean.
# The Python boolean values, True and False are the only valid values.
TYPES[bool] = gdb.PARAM_BOOLEAN

# The value is an integer.
# This is like PARAM_INTEGER, except 0 is interpreted as itself.
TYPES[int] = gdb.PARAM_ZINTEGER

# The value is a string.
# When the user modifies the string, any escape sequences,
# such as ‘\t’, ‘\f’, and octal escapes, are translated into
# corresponding characters and encoded into the current host charset.
TYPES[str] = gdb.PARAM_STRING

triggers = collections.defaultdict(lambda: [])


class Trigger:
    def __init__(self, names):
        if not isinstance(names, list):
            names = [names]
        names = list(map(lambda n: n.name if isinstance(n, Parameter) else n, names))
        self.names = list(map(lambda n: n.replace('-', '_'), names))

    def __call__(self, function):
        global triggers
        for name in self.names:
            triggers[name].append(function)
        return function


def get_param(value):
    for k, v in TYPES.items():
        if isinstance(value, k):
            return v


def get_params(scope):
    module_attributes = globals()['module'].__dict__.values()
    return sorted(filter(lambda p: isinstance(p, Parameter) and p.scope == scope, module_attributes))


def value_to_gdb_native(value):
    """Translates Python value into native GDB syntax string."""
    mapping = collections.OrderedDict()
    mapping[bool] = lambda value: 'on' if value else 'off'

    for k, v in mapping.items():
        if isinstance(value, k):
            return v(value)
    return value


member_remap = {
    'value': '_value',
    'raw_value': 'value'
}
@total_ordering
class Parameter(gdb.Parameter):
    """
    For python2, we can not store unicode type in self.value since the implementation limitation of gdb python.
    We use self._value as the converted cache and set __getattribute__() and __setattr__() to remap variables.

    Since GDB will set gdb.Parameter.value to user input and call get_set_string(),
    we use self.raw_value to map back to gdb.Parameter.value

    That is, we remap
    * Parameter.value -> gdb.Parameter._value (if it is string type, always keep unicode)
        All getter return this
    * Parameter.raw_value -> gdb.Parameter.value
        Only used in get_set_string()
    """
    def __init__(self, name, default, docstring, scope='config'):
        self.docstring = docstring.strip()
        self.optname = name
        self.name = name.replace('-', '_')
        self.default = default
        self.set_doc = 'Set ' + docstring
        self.show_doc = docstring + ':'
        super(Parameter, self).__init__(name,
                                        gdb.COMMAND_SUPPORT,
                                        get_param(default))
        self.value = default
        self.scope = scope
        setattr(module, self.name, self)

    @property
    def native_value(self):
        return value_to_gdb_native(self.value)

    @property
    def native_default(self):
        return value_to_gdb_native(self.default)

    @property
    def is_changed(self):
        return self.value != self.default

    def __setattr__(self, name, value):
        new_name = member_remap.get(name, name)
        new_name = str(new_name) # Python2 only accept str type as key
        return super(Parameter, self).__setattr__(new_name, value)

    def __getattribute__(self, name):
        new_name = member_remap.get(name, name)
        new_name = str(new_name) # Python2 only accept str type as key
        return super(Parameter, self).__getattribute__(new_name)

    def get_set_string(self):
        value = self.raw_value

        # For string value, convert utf8 byte string to unicode.
        if isinstance(value, bytes):
            value = codecs.decode(value, 'utf-8')

        # Remove surrounded ' and " characters
        if isinstance(value, str):
            # The first character must be ' or " and ends with the same character.
            # See PR #404 for more information
            pattern = r"^(?P<quote>[\"'])(?P<content>.*?)(?P=quote)$"

            value = re.sub(pattern, r"\g<content>", value)

        # Write back to self.value
        self.value = value

        for trigger in triggers[self.name]:
            trigger()

        if not pwndbg.decorators.first_prompt:
            return ''
        return 'Set %s to %r' % (self.docstring, self.value)

    def get_show_string(self, svalue):
        return 'Sets %s (currently: %r)' % (self.docstring, self.value)

    def revert_default(self):
        self.value = self.default

    # TODO: use __getattribute__ to remapping all member function to self.value's member?
    # Then, we can use param.member() just like param.value.member()

    # The str type member function, used in color/__init__.py
    def split(self, *args, **kargs):
        return str(self).split(*args, **kargs)

    # Casting
    def __int__(self):
        return int(self.value)

    def __str__(self):
        return str(self.value)

    def __bool__(self):
        return bool(self.value)

    # Compare operators
    # Ref: http://portingguide.readthedocs.io/en/latest/comparisons.html
    # If other is Parameter, comparing by optname. Used in `sorted` in `config` command.
    # Otherwise, compare `self.value` with `other`
    def __eq__(self, other):
        if isinstance(other, gdb.Parameter):
            return self.optname == other.optname
        else:
            return self.value == other

    def __lt__(self, other):
        if isinstance(other, gdb.Parameter):
            return self.optname < other.optname
        else:
            return self.value < other

    # Operators
    def __add__(self, other):
        return self.value + other

    def __radd__(self, other):
        return other + self.value

    def __sub__(self, other):
        return self.value - other

    def __rsub__(self, other):
        return other - self.value

    def __mul__(self, other):
        return self.value * other

    def __rmul__(self, other):
        return other * self.value

    def __div__(self, other):
        return self.value / other

    def __floordiv__(self, other):
        return self.value // other

    def __pow__(self, other):
        return self.value ** other

    def __mod__(self, other):
        return self.value % other

    def __len__(self):
        return len(self.value)

    # Python2 compatibility
    __nonzero__ = __bool__


class ConfigModule(types.ModuleType):
    def __init__(self, name, module):
        super(ConfigModule, self).__init__(name)
        self.__dict__.update(module.__dict__)

    Parameter = Parameter


# To prevent garbage collection
tether = sys.modules[__name__]

# Create the module structure
module = ConfigModule(__name__, tether)
sys.modules[__name__] = module
