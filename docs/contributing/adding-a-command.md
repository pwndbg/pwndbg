# Adding a Command

Create a new Python file in `pwndbg/commands/my_command.py`, replacing `my_command` with a reasonable name for the command. The most basic command looks like this:

```python
import argparse

import pwndbg.commands

parser = argparse.ArgumentParser(description="Command description.")
parser.add_argument("arg", type=str, help="An example argument.")


@pwndbg.commands.Command(parser)
def my_command(arg: str) -> None:
    """Print the argument"""
    print(f"Argument is {arg}")
```

In addition, you need to import this file in the `load_commands` function in `pwndbg/commands/__init__.py`. After this, running `my_command foo` in GDB or LLDB will print out "Argument is foo".
