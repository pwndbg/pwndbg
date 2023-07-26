from __future__ import annotations

import types


class Config(types.ModuleType):
    def __init__(self, module_name):
        super().__init__(module_name)

    def trigger(self, *args):
        def wrapper(func):
            return func

        return wrapper

    def add_param(self, *args, **kwargs):
        pass

    def add_param_obj(self, *args, **kwargs):
        pass

    def init_params(self):
        pass
