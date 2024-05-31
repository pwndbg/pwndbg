from __future__ import annotations

from collections import defaultdict
from functools import total_ordering
from typing import Any
from typing import Callable
from typing import DefaultDict
from typing import Dict
from typing import List
from typing import Sequence
from typing import TypeVar

T = TypeVar("T")

# Boolean value. True or False, same as in Python.
PARAM_BOOLEAN = 0
# Signed integer value.
PARAM_ZINTEGER = 1
# String value. Accepts escape sequences.
PARAM_STRING = 2
# Unsigned integer value.
PARAM_ZUINTEGER = 3
# String value, accepts only one of a number of possible values, specified at
# parameter creation.
PARAM_ENUM = 4
# String value corresponding to the name of a file, if present.
PARAM_OPTIONAL_FILENAME = 5
# Boolean value, or 'auto'.
PARAM_AUTO_BOOLEAN = 6
# Unlimited ZUINTEGER.
PARAM_ZUINTEGER_UNLIMITED = 7
# Signed integer value. Disallows zero.
PARAM_INTEGER = 8
# Unsigned integer value. Disallows zero.
PARAM_UINTEGER = 9

PARAM_CLASSES = {
    # The Python boolean values, True and False are the only valid values.
    bool: PARAM_BOOLEAN,
    # This is like PARAM_INTEGER, except 0 is interpreted as itself.
    int: PARAM_ZINTEGER,
    # When the user modifies the string, any escape sequences,
    # such as ‘\t’, ‘\f’, and octal escapes, are translated into
    # corresponding characters and encoded into the current host charset.
    str: PARAM_STRING,
}
# @total_ordering allows us to implement `__eq__` and `__lt__` and have all the
# other comparison operators handled for us
@total_ordering
class Parameter:
    def __init__(
        self,
        name: str,
        default: Any,
        set_show_doc: str,
        *,
        help_docstring: str = "",
        param_class: int | None = None,
        enum_sequence: Sequence[str] | None = None,
        scope: str = "config",
    ) -> None:
        # Note: `set_show_doc` should be a noun phrase, e.g. "the value of the foo"
        # The `set_doc` will be "Set the value of the foo."
        # The `show_doc` will be "Show the value of the foo."
        # `get_set_string()` will return "Set the value of the foo to VALUE."
        # `get_show_string()` will return "Show the value of the foo."
        self.set_show_doc = set_show_doc.strip()
        self.help_docstring = help_docstring.strip()
        self.name = name
        self.default = default
        self.value = default
        self.param_class = param_class or PARAM_CLASSES[type(default)]
        self.enum_sequence = enum_sequence
        self.scope = scope

    @property
    def is_changed(self) -> bool:
        return self.value != self.default

    def revert_default(self) -> None:
        self.value = self.default

    def attr_name(self) -> str:
        """Returns the attribute name associated with this config option,
        i.e. `my-config` has the attribute name `my_config`"""
        return self.name.replace("-", "_")

    def __getattr__(self, name: str):
        return getattr(self.value, name)

    # Casting
    def __int__(self) -> int:
        return int(self.value)

    def __str__(self) -> str:
        return str(self.value)

    def __bool__(self) -> bool:
        return bool(self.value)

    # Compare operators
    # Ref: http://portingguide.readthedocs.io/en/latest/comparisons.html

    # If comparing with another `Parameter`, the `Parameter` objects are equal
    # if they refer to the same GDB parameter. For any other type of object, the
    # `Parameter` is equal to the object if `self.value` is equal to the object
    def __eq__(self, other: object) -> bool:
        if isinstance(other, Parameter):
            return self.name == other.name
        return self.value == other

    def __lt__(self, other: object) -> bool:
        if isinstance(other, Parameter):
            return self.name < other.name
        return self.value < other

    # Operators
    def __add__(self, other: int) -> int:
        return self.value + other

    def __radd__(self, other: int) -> int:
        return other + self.value

    def __sub__(self, other: int) -> int:
        return self.value - other

    def __rsub__(self, other: int) -> int:
        return other - self.value

    def __mul__(self, other: int) -> int:
        return self.value * other

    def __rmul__(self, other: int) -> str:
        return other * self.value

    def __div__(self, other: float) -> float:
        return self.value / other

    def __floordiv__(self, other: int) -> int:
        return self.value // other

    def __pow__(self, other: int) -> int:
        return self.value**other

    def __mod__(self, other: int) -> int:
        return self.value % other

    def __len__(self) -> int:
        return len(self.value)


class Config:
    def __init__(self) -> None:
        self.params: Dict[str, Parameter] = {}
        self.triggers: DefaultDict[str, List[Callable[..., Any]]] = defaultdict(list)

    def add_param(
        self,
        name: str,
        default: Any,
        set_show_doc: str,
        *,
        help_docstring: str = "",
        param_class: int | None = None,
        enum_sequence: Sequence[str] | None = None,
        scope: str = "config",
    ) -> Parameter:
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

    def add_param_obj(self, p: Parameter) -> Parameter:
        attr_name = p.attr_name()

        # Make sure this isn't a duplicate parameter
        assert attr_name not in self.params

        self.params[attr_name] = p
        return p

    def trigger(self, *params: Parameter) -> Callable[[Callable[..., T]], Callable[..., T]]:
        names = [p.name for p in params]

        def wrapper(func: Callable[..., T]) -> Callable[..., T]:
            for name in names:
                self.triggers[name].append(func)
            return func

        return wrapper

    def get_params(self, scope: str) -> List[Parameter]:
        return sorted(filter(lambda p: p.scope == scope, self.params.values()))

    def __getattr__(self, name: str) -> Parameter:
        if name in self.params:
            return self.params[name]
        else:
            raise AttributeError(f"'Config' object has no attribute '{name}'")
