import collections
from functools import total_ordering
from typing import List


# @total_ordering allows us to implement `__eq__` and `__lt__` and have all the
# other comparison operators handled for us
@total_ordering
class Parameter:
    def __init__(self, name, default, docstring, scope="config"):
        self.docstring = docstring.strip()
        self.name = name
        self.default = default
        self.value = default
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

    def add_param(self, name, default, docstring, scope="config"):
        # Dictionary keys are going to have underscores, so we can't allow them here
        assert "_" not in name

        p = Parameter(name, default, docstring, scope)
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
