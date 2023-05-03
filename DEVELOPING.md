- [Development Basics](#development-basics)
  * [Environment setup](#environment-setup)
  * [Testing](#testing)
  * [Linting](#linting)
  * [Minimum Supported Versions](#minimum-supported-versions)
- [Adding a Command](#adding-a-command)
- [Adding a Configuration Option](#adding-a-configuration-option)
  * [Configuration Docstrings](#configuration-docstrings)
  * [Triggers](#triggers)
- [Random developer notes](#random-developer-notes)

# Development Basics
## Environment setup

After installing `pwndbg` by running `setup.sh`, you additionally need to run `./setup-dev.sh` to install the necessary development dependencies.

If you would like to use Docker, you can create a Docker image with everything already installed for you. To do this, run the following command:
```bash
docker run -it --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v `pwd`:/pwndbg pwndbg bash
```

If you'd like to use `docker compose`, you can run
```bash
docker compose run -i main
```

## Testing

It's highly recommended you write a new test or update an existing test whenever adding new functionality to `pwndbg`.

Tests are located in [`tests/gdb-tests`](tests/gdb-tests). `tests/unit-tests` also exists, but the unit testing framework is not complete and so it should not be used.

To run the tests, run [`./tests.sh`](./tests.sh). You can filter the tests to run by providing an argument to the script, such as `./tests.sh heap`, which will only run tests that contain "heap" in the name. You can also drop into the PDB debugger when a test fails with `./tests.sh --pdb`.

Our tests are written using [`pytest`](https://docs.pytest.org/en/latest/). It uses some magic so that Python's `assert` can be used for asserting things in tests and it injects dependencies which are called fixtures, into test functions. These fixtures are defined in [`tests/conftest.py`](tests/conftest.py).

We can take a look at [`tests/gdb-tests/tests/test_hexdump.py`](tests/gdb-tests/tests/test_hexdump.py) for an example of a simple test. Looking at a simplified version of the top-level code, we have this:
```python
import gdb
import tests

BINARY = tests.binaries.get("reference-binary.out")
```

Since these tests run inside GDB, we can import the `gdb` Python library. We also import the `tests` module, which makes it easy to get the path to the test binaries located in [`tests/gdb-tests/tests/binaries`](tests/gdb-tests/tests/binaries). You should be able to reuse the binaries in this folder for most tests, but if not feel free to add a new one.

Here's a small snippet of the actual test:
```python
def test_hexdump(start_binary):
    start_binary(BINARY)
    pwndbg.gdblib.config.hexdump_group_width = -1

    gdb.execute("set hexdump-byte-separator")
    stack_addr = pwndbg.gdblib.regs.rsp - 0x100
```

`pytest` will run any function that starts with `test_` as a new test, so there is no need to register your new test anywhere. The `start_binary` argument is a function that will run the binary you give it, and it will set some common options before starting the binary. Using `start_binary` is recommended if you don't need any additional customization to GDB settings before starting the binary, but if you do it's fine to not use it.

Note that in the test, we can access `pwndbg` library code like `pwndbg.gdblib.regs.rsp` as well as execute GDB commands with `gdb.execute()`.

## Linting

The `lint.sh` script runs `isort`, `black`, `ruff`, `shfmt`, and `vermin`. `isort` and `black` are able to automatically fix any issues they detect, and you can enable this by running `./lint.sh -f`. You can find the configuration files for these tools in `setup.cfg` and `pyproject.toml`.

When submitting a PR, the CI job defined in `.github/workflows/lint.yml` will verify that running `./lint.sh` succeeds, otherwise the job will fail and we won't be able to merge your PR.

You can optionally set the contents of `.git/hooks/pre-push` to the following if you would like `lint.sh` to automatically be run before every push:
```bash
#!/bin/sh

./lint.sh || exit 1
```

## Minimum Supported Versions

Our goal is to fully support all Ubuntu LTS releases that have not reach end-of-life, with support for other platforms on a best-effort basis. Currently that means all code should work on Ubuntu 18.04, 20.04, and 22.04 with GDB 8.1 and later. This means that the minimum supported Python version is 3.6.9, and we cannot use any newer Python features unless those features are backported to this minimum version.

Note that while all code should run without errors on these supported LTS versions, it's fine if older versions don't support all of the features of newer versions, as long as this is handled correctly and this information is shown to the user. For example, we may make use of some GDB APIs in newer versions that we aren't able to provide alternative implementations for in older versions, and so in these cases we should inform the user that the functionality can't be provided due to the version of GDB.

The `lint.sh` script described in the previous section runs [`vermin`](https://github.com/netromdk/vermin) to ensure that our code does not use any features that aren't supported on Python 3.6.

# Adding a Command

Create a new Python file in `pwndbg/commands/my_command.py`, replacing `my_command` with a reasonable name for the command. The most basic command looks like this:

```python
import argparse

import pwndbg.commands

parser = argparse.ArgumentParser(description="Command description.")
parser.add_argument("arg", type=str, help="An example argument.")


@pwndbg.commands.ArgparsedCommand(parser)
def my_command(arg: str) -> None:
    """Print the argument"""
    print(f"Argument is {arg}")
```

In addition, you need to import this file in the `load_commands` function in `pwndbg/commands/__init__.py`. After this, running `my_command foo` in GDB will print out "Argument is foo".

# Adding a Configuration Option

```python
import pwndbg.gdblib.config

pwndbg.gdblib.config.add_param("config-name", False, "example configuration option")
```

`pwndbg.gdblib.config.config_name` will now refer to the value of the configuration option, and it will default to `False` if not set.

## Configuration Docstrings

TODO: There are many places GDB shows docstrings, and they show up slightly differently in each place, we should give examples of this

* When using `pwndbg.gdblib.config.add_param` to add a new config, there are a few things to keep in mind:
  * For the `set_show_doc` parameter, it is best to use a noun phrase like "the value of something" to ensure that the output is grammatically correct.
  * For the `help_docstring` parameter, you can use the output of `help set follow-fork-mode` as a guide for formatting the documentation string if the config is an enum type.
  * For the `param_class` parameter
    * See the [documentation](https://sourceware.org/gdb/onlinedocs/gdb/Parameters-In-Python.html) for more information.
    * If you use `gdb.PARAM_ENUM` as `param_class`, you must pass a list of strings to the `enum_sequence` parameter.

## Triggers

TODO: If we want to do something when user changes config/theme - we can do it defining a function and decorating it with `pwndbg.config.Trigger`.

# Random developer notes

Feel free to update the list below!

* If you want to play with pwndbg functions under GDB, you can always use GDB's `pi` which launches python interpreter or just `py <some python line>`.

* If there is possibility, don't use `gdb.execute` as this requires us to parse the string and so on; there are some cases in which there is no other choice. Most of the time we try to wrap GDB's API to our own/easier API.

* We have our own `pwndbg.config.Parameter` (which extends `gdb.Parameter`) - all of our parameters can be seen using `config` or `theme` commands. 

* The dashboard/display/context we are displaying is done by `pwndbg/commands/context.py` which is invoked through GDB's prompt hook (which we defined in `pwndbg/prompt.py` as `prompt_hook_on_stop`).

* We change a bit GDB settings - this can be seen in `pwndbg/__init__.py` - there are also imports for all pwndbg submodules

* We have a wrapper for GDB's events in `pwndbg/events.py` - thx to that we can e.g. invoke something based upon some event

* We have a caching mechanism (["memoization"](https://en.wikipedia.org/wiki/Memoization)) which we use through Python's decorators - those are defined in `pwndbg/lib/cache.py` - just check its usages

* To block a function before the first prompt was displayed use the `pwndbg.decorators.only_after_first_prompt` decorator.

* Memory accesses should be done through `pwndbg/memory.py` functions

* Process properties can be retrieved thx to `pwndbg/gdblib/proc.py` - e.g. using `pwndbg.gdblib.proc.pid` will give us current process pid

* We have a wrapper for handling exceptions that are thrown by commands - defined in `pwndbg/exception.py` - current approach seems to work fine - by using `set exception-verbose on` - we get a stacktrace. If we want to debug stuff we can always do `set exception-debugger on`.

* Some of pwndbg's functionality - e.g. memory fetching - require us to have an instance of proper `gdb.Type` - the problem with that is that there is no way to define our own types - we have to ask gdb if it detected particular type in this particular binary (that sucks). We do it in `pwndbg/typeinfo.py` and it works most of the time. The known bug with that is that it might not work properly for Golang binaries compiled with debugging symbols.

* If you want to use `gdb.parse_and_eval("a_function_name()")` or something similar that call a function, please remember this might cause another thread to continue execution without `set scheduler-locking on`. If you didn't expect that, you should use `parse_and_eval_with_scheduler_lock` from `pwndbg.gdblib.scheduler` instead.
