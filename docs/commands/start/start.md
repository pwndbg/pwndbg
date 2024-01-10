



# start

## Description



Start the debugged program stopping at the first convenient location
from this list: main, _main, start, _start, init or _init.
You may specify arguments to give it.

Args may include "*", or "[...]"; they are expanded using the
shell that will start the program (specified by the "$SHELL" environment
variable).  Input and output redirection with ">", "<", or ">>"
are also allowed.

With no arguments, uses arguments last specified (with "run" or
"set args").  To cancel previous arguments and run with no arguments,
use "set args" without arguments.

To start the inferior without using a shell, use "set startup-with-shell off".

## Usage:


```bash
usage: start [-h] [args ...]

```
## Positional Arguments

|Positional Argument|Help|
| :--- | :--- |
|`args`|The arguments to run the binary with.|

## Optional Arguments

|Short|Long|Default|Help|
| :--- | :--- | :--- | :--- |
|`-h`|`--help`||show this help message and exit|
