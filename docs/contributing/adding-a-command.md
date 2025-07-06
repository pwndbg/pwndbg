# Adding a Command
## Command skeleton
To add a command to Pwndbg, create a new python file in `pwndbg/commands/my_command.py` where `my_command` is the name of the command you want to add.  The most basic command looks like this:
```python
import argparse
import pwndbg.commands

parser = argparse.ArgumentParser(description="Command description.")
parser.add_argument("arg", type=str, help="An example argument.")

@pwndbg.commands.Command(parser, category=pwndbg.commands.CommandCategory.MISC)
def my_command(arg: str) -> None:
    """Print the argument"""
    print(f"Argument is {arg}")
```
Next, import this file in the `load_commands` function in `pwndbg/commands/__init__.py`.

That's all you need to get it working!
```text
pwndbg> my-command foo
Argument is foo
```
## Getting started
Let's see what arguments the `@pwndbg.commands.Command` decorator takes. It is defined in `pwndbg/commands/__init__.py`:
```python
    def __init__(
        self,
        parser_or_desc: argparse.ArgumentParser | str,
        *,  # All further parameters are not positional
        category: CommandCategory,
        command_name: str | None = None,
        aliases: List[str] = [],
        examples: str = "",
        notes: str = "",
        only_debuggers: Set[pwndbg.dbg_mod.DebuggerType] = None,
        exclude_debuggers: Set[pwndbg.dbg_mod.DebuggerType] = None,
	) -> None:
		# ...
```
We will cover the first four arguments now, and come back to the rest later.

If your command takes no arguments you can pass the description of the command as the first argument (`parser_or_desc`) to the constructor. Otherwise you will be passing an [`argparse.ArgumentParser`](https://docs.python.org/3/library/argparse.html#argparse.ArgumentParser) object there.

The only other required argument is `category`. The `category` determines how commands are grouped together in the output of the [`pwndbg`](https://pwndbg.re/pwndbg/dev/commands/pwndbg/pwndbg/) command and in the [documentation](https://pwndbg.re/pwndbg/dev/commands/). Peruse the list of all commands inside a debugger (by running the `pwndbg` command) and decide in which category your command fits best. The enum of all command categories is defined at the top of the `pwndbg/commands/__init__.py` file.
### Picking a command name
Next, the `command_name` argument. It is optional because if it is not specified the command name will be the same as the function you used to define the command (except the underscores are replaced with dashes). As such, it is generally not needed to specify this argument.

That being said, it is important to pick a good name for your command. Ideally your command name should be one to two words that are *not* delimited by a dash (e.g. `errno`, `libcinfo`, `buddydump`) since that is easiest to remember and type.

If your command is porting behavior from some other debugger or tool, you should consider using the same name they use so users don't need to relearn it when switching.

If the command name contains three or more words, you should use dashes to make it more legible. If that is the case, or if the name is long, consider providing an alias that makes it quicker to type (like `vis-heap-chunks [vis]`).

You provide aliases to a command by specifying a list of strings to the `aliases` argument. Again, you may provide aliases to help users transitioning from other tools/debuggers (e.g. `nearpc [pdisass, u]`).
## The arguments your command will take
We are using [`argparse.ArgumentParser`](https://docs.python.org/3/library/argparse.html#argparse.ArgumentParser) from the python standard library to define command arguments. Take a look at the python documentation to see how it works. Let's take a look at an example from the source (the [`setflag`](https://pwndbg.re/pwndbg/dev/commands/register/setflag/) command):
```python
parser = argparse.ArgumentParser(description="Modify the flags register.")

parser.add_argument(
	"flag",
	type=str,
	help="Flag for which you want to change the value"
 )

parser.add_argument(
    "value",
    type=int,
    help="Value to which you want to set the flag - only valid options are 0 and 1",
)
```
For usage inside Pwndbg, to instantiate an `argparse.ArgumentParser` object, you must pass the `description` argument and may pass the `epilog` argument. Everything else, including `prog`, `usage`, `formatter_class` etc. will be set up by Pwndbg (by the `@pwndbg.commands.Command` decorator). Here we see only the `description` was provided.

Add arguments to your command with [`parser.add_argument`](https://docs.python.org/3/library/argparse.html#the-add-argument-method). Again, consult the python documentation for an explanation. One nice thing specific to Pwndbg is that by setting an argument's `type` to `int`, it will also accept debugger values and symbols that can resolve to an int. For instance:
```python
pwndbg> setflag ZF (1-1)
Set flag ZF=0 in flag register eflags (old val=0x206, new val=0x206)
pwndbg> setflag ZF $rdi
Set flag ZF=1 in flag register eflags (old val=0x246, new val=0x246)
pwndbg> setflag ZF (int)main^(int)main
Set flag ZF=0 in flag register eflags (old val=0x246, new val=0x206)
```
Be careful when deciding which arguments are positional, and which are optional. Especially take care if you have positional arguments which are not required, think about which of those will be specified more often by users and put them first.

Your function signature should match the arguments you defined with argparse (and their order!), unsurprisingly the `setflag` function has this signature:
```python
def setflag(flag: str, value: int) -> None:
```
You can see the help of your command with `my_command -h` or `help my_command`, so for `setflag`:
```
pwndbg> help setflag
usage: setflag [-h] flag value

Modify the flags register.

positional arguments:
  flag        Flag for which you want to change the value
  value       Value to which you want to set the flag - only valid options are 0 and 1

options:
  -h, --help  show this help message and exit

Examples:
On X86/X64:
    setflag ZF 1        -- set zero flag
    setflag CF 0        -- unset carry flag

On ARM:
    setflag Z 0         -- unset the Z cpsr/xpsr flag

To see flags registers:
    info reg eflags     -- on x86/x64
    info reg cpsr/xpsr  -- on ARM (specific register may vary)

Notes:
This command supports flags registers that are defined for architectures in the pwndbg/regs.py file.

Alias: flag
```
Eh? Where is all that extra text coming from? Well the `Alias: flag` line is being automatically generated by Pwndbg but...
## Examples, notes, and debugger support
Coming back to the arguments of the `pwndbg.commands.Command` constructor:
```python
    def __init__(
        self,
        parser_or_desc: argparse.ArgumentParser | str,
        *,  # All further parameters are not positional
        category: CommandCategory,
        command_name: str | None = None,
        aliases: List[str] = [],
        examples: str = "",  #  <--- we left off here
        notes: str = "",
        only_debuggers: Set[pwndbg.dbg_mod.DebuggerType] = None,
        exclude_debuggers: Set[pwndbg.dbg_mod.DebuggerType] = None,
	) -> None:
		# ...
```
You may supply the `examples` and `notes` arguments to add additional text at the end of the command's help. It is defined like so for `setflag`:
```python
@pwndbg.commands.Command(
    parser,
    aliases=["flag"],
    category=CommandCategory.REGISTER,
    examples="""
On X86/X64:
    setflag ZF 1        -- set zero flag
    setflag CF 0        -- unset carry flag

On ARM:
    setflag Z 0         -- unset the Z cpsr/xpsr flag

To see flags registers:
    info reg eflags     -- on x86/x64
    info reg cpsr/xpsr  -- on ARM (specific register may vary)
    """,
    notes="""
This command supports flags registers that are defined for architectures in the pwndbg/regs.py file.
    """,
)
@pwndbg.commands.OnlyWhenRunning
def setflag(flag: str, value: int) -> None:
	# ....
```
When writing this (and the command description for that matter), you should consider what it will [look like in the documentation](https://pwndbg.re/pwndbg/dev/commands/register/setflag/) after being parsed as markdown.

As for `only_debuggers` and `exclude_debuggers`, you must use (usually one of) them if your command does not work an all debuggers that Pwndbg supports. For instance, if it uses some features from `pwndbg.gdblib` (which should be avoided if at all possible). In such a case, you probably also need to conditionally import it in the `load_commands` function.
## Can your command be invoked all the time?
In most cases a command cannot be legally invoked at every moment in a debugging session, or for every debugging session. For instance, you can't use heap commands if the heap isn't initialized yet, you can't use kernel commands if you're not debugging a kernel.

To make sure these cases are properly handled, Pwndbg provides certain decorators. They are defined in `pwndbg/commands/__init__.py`. Check the source to see an up-to-date list, but here are some important ones:
```
OnlyWhenRunning
OnlyWhenLocal
OnlyWithFile
OnlyWhenQemuKernel
OnlyWhenUserspace
OnlyWithKernelDebugInfo
OnlyWithKernelDebugSymbols
OnlyWhenPagingEnabled
OnlyWithTcache
OnlyWhenHeapIsInitialized
OnlyWithResolvedHeapSyms
```
Feel free to add more of these decorators yourself!

Another very important one is `OnlyWithArch`, defined in `pwndbg/aglib/proc.py`. Does your command work on all architectures? If not, make sure to specify this decorator and pass in the architectures which you do support.
## Actually implementing the command
There is no single right way to do it. You will want to read the source of some similar commands and see how they work. Check out the [general developer notes](dev-notes.md), and feel free to ask a question on the [discord server](https://discord.gg/x47DssnGwm). Good luck!
