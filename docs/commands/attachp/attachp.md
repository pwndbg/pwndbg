



# attachp

## Description


Attaches to a given pid, process name or device file.

This command wraps the original GDB `attach` command to add the ability
to debug a process with given name. In such case the process identifier is
fetched via the `pidof <name>` command.

Original GDB attach command help:
    Attach to a process or file outside of GDB.
    This command attaches to another target, of the same type as your last
    "target" command ("info files" will show your target stack).
    The command may take as argument a process id or a device file.
    For a process id, you must have permission to send the process a signal,
    and it must have the same effective uid as the debugger.
    When using "attach" with a process id, the debugger finds the
    program running in the process, looking first in the current working
    directory, or (if not found there) using the source file search path
    (see the "directory" command).  You can also use the "file" command
    to specify the program, and to load its symbol table.
## Usage:


```bash
usage: attachp [-h] [--no-truncate] target

```
## Positional Arguments

|Positional Argument|Help|
| :--- | :--- |
|`target`|pid, process name or device file to attach to|

## Optional Arguments

|Short|Long|Default|Help|
| :--- | :--- | :--- | :--- |
|`-h`|`--help`||show this help message and exit|
||`--no-truncate`||dont truncate command args (default: %(default)s)|
