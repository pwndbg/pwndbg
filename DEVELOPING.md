# Random developer notes

Feel free to update the list below!

* If you want to play with pwndbg functions under GDB, you can always use GDB's `pi` which launches python interpreter or just `py <some python line>`.

* If there is possibility, don't use `gdb.execute` as this requires us to parse the string and so on; there are some cases in which there is no other choice. Most of the time we try to wrap GDB's API to our own/easier API.

* We have our own `pwndbg.config.Parameter` (which extends `gdb.Parameter`) - all of our parameters can be seen using `config` or `theme` commands. If we want to do something when user changes config/theme - we can do it defining a function and decorating it with `pwndbg.config.Trigger`.

* The dashboard/display/context we are displaying is done by `pwndbg/commands/context.py` which is invoked through GDB's prompt hook (which we defined in `pwndbg/prompt.py` as `prompt_hook_on_stop`).

* All commands should be defined in `pwndbg/commands` - most of them lie in seperate files but some files contains many of them (e.g. commands corresponding to windbg debugger - in `windbg.py` or some misc commands in `misc.py`). We would also want to make all of them to use `ArgparsedCommand` (instead of `Command` or `ParsedCommand` decorators).

* We change a bit GDB settings - this can be seen in `pwndbg/__init__.py` - there are also imports for all pwndbg submodules

* We have a wrapper for GDB's events in `pwndbg/events.py` - thx to that we can e.g. invoke something based upon some event

* We have a caching mechanism (["memoization"](https://en.wikipedia.org/wiki/Memoization)) which we use through Python's decorators - those are defined in `pwndbg/memoize.py` - just check its usages

* To block a function before the first prompt was displayed use the `pwndbg.decorators.only_after_first_prompt` decorator.

* Memory accesses should be done through `pwndbg/memory.py` functions

* Process properties can be retrieved thx to `pwndbg/proc.py` - e.g. using `pwndbg.proc.pid` will give us current process pid

* We have an inthook to make it easier to work with Python 2 and gdb.Value objects - see the docstring in `pwndbg/inthook.py` . Specifically, it makes it so that you can call `int()` on a `gdb.Value` instance and get what you want. 

* We have a wrapper for handling exceptions that are thrown by commands - defined in `pwndbg/exception.py` - current approach seems to work fine - by using `set exception-verbose on` - we get a stacktrace. If we want to debug stuff we can always do `set exception-debugger on`.

* Some of pwndbg's functionality - e.g. memory fetching - require us to have an instance of proper `gdb.Type` - the problem with that is that there is no way to define our own types - we have to ask gdb if it detected particular type in this particular binary (that sucks). We do it in `pwndbg/typeinfo.py` and it works most of the time. The known bug with that is that it might not work properly for Golang binaries compiled with debugging symbols.

* We would like to add proper tests for pwndbg - see tests framework PR if you want to help on that.

# Testing

Our tests are written using [pytest](https://docs.pytest.org/en/latest/). It uses some magic so that Python's `assert` can be used for asserting things in tests and it injects dependencies which are called fixtures, into test functions.

The fixtures should be defined in [tests/conftest.py](tests/conftest.py). If you need help with writing tests, feel free to reach out on gitub issues/pr or on our irc channel on freenode.
