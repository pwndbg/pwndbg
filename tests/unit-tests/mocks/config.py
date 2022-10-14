import types


class Config(types.ModuleType):
    def __init__(self, module_name):
        super(Config, self).__init__(module_name)

    def trigger(self, *args):
        def wrapper(func):
            return func

        return wrapper

    def add_param(self, *args):
        pass

    def init_params(self):
        pass
