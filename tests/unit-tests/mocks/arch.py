import types


class Amd64Arch(types.ModuleType):
    def __init__(self, module_name):
        super(Amd64Arch, self).__init__(module_name)

        self.ptrsize = 8
        self.endian = "little"
