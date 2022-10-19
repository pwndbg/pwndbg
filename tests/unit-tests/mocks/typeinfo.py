import types


class Amd64TypeInfo(types.ModuleType):
    def __init__(self, module_name):
        super(Amd64TypeInfo, self).__init__(module_name)
        self.ptrsize = 8
