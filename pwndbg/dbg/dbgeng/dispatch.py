from typing import Callable


class CommandDispatcher:
    def __init__(self):
        self.handlers = {}

    def register(self, command_name: str, handler: Callable[[str, bool], None]):
        self.handlers[command_name] = handler

    def dispatch(self, command_name: str, args: str):
        assert command_name in self.handlers
        handler = self.handlers[command_name]
        handler(args, True) # True indicates interactive
