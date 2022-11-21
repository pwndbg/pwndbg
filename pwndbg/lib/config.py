import collections
from functools import total_ordering
from typing import List

import gdb

PARAM_CLASSES = {
    # The Python boolean values, True and False are the only valid values.
    bool: gdb.PARAM_BOOLEAN,
    # This is like PARAM_INTEGER, except 0 is interpreted as itself.
    int: gdb.PARAM_ZINTEGER,
    # When the user modifies the string, any escape sequences,
    # such as ‘\t’, ‘\f’, and octal escapes, are translated into
    # corresponding characters and encoded into the current host charset.
    str: gdb.PARAM_STRING,
}


# @total_ordering allows us to implement `__eq__` and `__lt__` and have all the
# other comparison operators handled for us
@total_ordering
class Parameter:
    def __init__(
        self,
        name,
        default,
        set_show_doc,
        *,
        help_docstring=None,
        param_class=None,
        enum_sequence=None,
        scope="config",
    ):
        self.set_show_doc = set_show_doc.strip()
        self.help_docstring = help_docstring.strip() if help_docstring else None
        self.name = name
        self.default = default
        self.value = default
        self.param_class = param_class or PARAM_CLASSES[type(default)]
        self.enum_sequence = enum_sequence
        self.scope = scope

    @property
    def is_changed(self):
        return self.value != self.default

    def revert_default(self):
        self.value = self.default

    def attr_name(self):
        """Returns the attribute name associated with this config option,
        i.e. `my-config` has the attribute name `my_config`"""
        return self.name.replace("-", "_")

    def __getattr__(self, name):
        return getattr(self.value, name)

    # Casting
    def __int__(self):
        return int(self.value)

    def __str__(self):
        return str(self.value)

    def __bool__(self):
        return bool(self.value)

    # Compare operators
    # Ref: http://portingguide.readthedocs.io/en/latest/comparisons.html

    # If comparing with another `Parameter`, the `Parameter` objects are equal
    # if they refer to the same GDB parameter. For any other type of object, the
    # `Parameter` is equal to the object if `self.value` is equal to the object
    def __eq__(self, other):
        if isinstance(other, Parameter):
            return self.name == other.name

        return self.value == other

    def __lt__(self, other):
        if isinstance(other, Parameter):
            return self.name < other.name

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
        return self.value**other

    def __mod__(self, other):
        return self.value % other

    def __len__(self):
        return len(self.value)


class Config:
    def __init__(self):
        self.params = {}
        self.triggers = collections.defaultdict(lambda: [])

    def add_param(
        self,
        name,
        default,
        set_show_doc,
        *,
        help_docstring=None,
        param_class=None,
        enum_sequence=None,
        scope="config",
    ):
        # Dictionary keys are going to have underscores, so we can't allow them here
        assert "_" not in name

        p = Parameter(
            name,
            default,
            set_show_doc,
            help_docstring=help_docstring,
            param_class=param_class,
            enum_sequence=enum_sequence,
            scope=scope,
        )
        return self.add_param_obj(p)

    def add_param_obj(self, p: Parameter):
        attr_name = p.attr_name()

        # Make sure this isn't a duplicate parameter
        assert attr_name not in self.params

        self.params[attr_name] = p
        return p

    def trigger(self, *params: List[Parameter]):
        names = [p.name for p in params]

        def wrapper(func):
            for name in names:
                self.triggers[name].append(func)
            return func

        return wrapper

    def get_params(self, scope) -> List[Parameter]:
        return sorted(filter(lambda p: p.scope == scope, self.params.values()))

    def __getattr__(self, name):
        if name in self.params:
            return self.params[name]
        else:
            raise AttributeError("'Config' object has no attribute '%s'" % name)
