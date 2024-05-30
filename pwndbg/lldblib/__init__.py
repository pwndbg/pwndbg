
def register_class_as_cmd(debugger, cmd, c):
    mod = c.__module__
    name = c.__qualname__
    name = f"{mod if mod else ''}.{name}"

    print(debugger.HandleCommand(f"command script add -c {name} -s synchronous {cmd}"))
    

