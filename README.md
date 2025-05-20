![repository-open-graph](https://github.com/pwndbg/pwndbg/assets/150354584/77b2e438-898f-416f-a989-4bef30759627)
# pwndbg

[![license](https://img.shields.io/github/license/mashape/apistatus.svg?maxAge=2592000)](https://choosealicense.com/licenses/mit/)
[![Unit tests](https://github.com/pwndbg/pwndbg/actions/workflows/tests.yml/badge.svg?branch=dev&event=push)](https://github.com/pwndbg/pwndbg/actions/workflows/tests.yml)
[![codecov.io](https://codecov.io/github/pwndbg/pwndbg/branch/dev/badge.svg?token=i1cBPFVCav)](https://app.codecov.io/github/pwndbg/pwndbg/tree/dev)
[![Discord](https://img.shields.io/discord/843809097920413717?label=Discord&style=plastic)](https://discord.gg/x47DssnGwm)

`pwndbg` (/paʊnˈdiˌbʌɡ/) is a GDB and LLDB plug-in that makes debugging suck less,
with a focus on features needed by low-level software developers, hardware hackers,
reverse-engineers and exploit developers.

It has a boatload of features, see [FEATURES.md](https://github.com/pwndbg/pwndbg/blob/dev/FEATURES.md) and [CHEATSHEET][CHEATSHEET]
(feel free to print it!).

[CHEATSHEET]: https://drive.google.com/file/d/16t9MV8KTFXK7oX_CzXhmDdaVnjT8IYM4/view?usp=drive_link

## Why?

Vanilla GDB and LLDB are terrible to use for reverse engineering and exploit development.
Typing `x/g30x $esp` or navigating cumbersome LLDB commands is not fun and often provides
minimal information. The year is 2025, and core debuggers still lack many user-friendly
features such as a robust hexdump command. Windbg users are completely lost when they
occasionally need to bump into GDB or LLDB.

## What?

Pwndbg is a Python module which is loaded directly into GDB or LLDB*. It provides a suite
of utilities and enhancements that fill the gaps left by these debuggers, smoothing out
rough edges and making them more user-friendly.

Many other projects from the past (e.g., [gdbinit][gdbinit], [PEDA][PEDA]) and present
(e.g. [GEF][GEF]) exist to fill some these gaps. Each provides an excellent experience
and great features -- but they're difficult to extend (some are unmaintained, and all
are a single [100KB][gdbinit2], [200KB][peda.py], or [363KB][gef.py] file (respectively)).

Pwndbg exists not only to replace all of its predecessors, but also to have a clean
implementation that runs quickly and is resilient against all the weird corner cases
that come up.  It also comes batteries-included, so all of its features are available
if you run `setup.sh`.

[gdbinit]: https://github.com/gdbinit/Gdbinit
[gdbinit2]: https://github.com/gdbinit/Gdbinit/blob/master/gdbinit

[PEDA]: https://github.com/longld/peda
[peda.py]: https://github.com/longld/peda/blob/master/peda.py

[GEF]: https://github.com/hugsy/gef
[gef.py]: https://github.com/hugsy/gef/blob/master/gef.py

## When to Use GDB or LLDB?

Pwndbg supports both GDB and LLDB, and each debugger has its own strengths.
Here's a quick guide to help you decide which one to use:

| Use Case                                        | Supported Debugger   |
|-------------------------------------------------|----------------------|
| Debugging Linux binaries or ELF files           | **GDB**, **LLDB**    |
| Debugging Mach-O binaries on macOS              | **LLDB**             |
| Linux kernel debugging (qemu-system)            | **GDB**, **LLDB**    |
| Linux user-space emulation (qemu-user)          | **GDB**              |
| Embedded debugging (ARM Cortex M* or RISC-V/32) | **GDB**, **LLDB**    |

Pwndbg ensures a consistent experience across both, so switching between them is seamless.
> The LLDB implementation in Pwndbg is still in early-stage and may contain bugs or limitations.<br/>
> Known issues are tracked in [GitHub Issues][lldb_tracker].
>
> If you encounter any problems, feel free to report them or discuss on our [Discord server][discord].

[lldb_tracker]: https://github.com/pwndbg/pwndbg/issues?q=is%3Aissue%20state%3Aopen%20label%3A%22LLDB%20Port%22

### Compatibility Table
| Feature     | Supported Version               | Notes                                |
|-------------|---------------------------------|--------------------------------------|
| pwndbg-gdb  | - Python 3.10+ <br/>- GDB 12.1+ | Battle-tested on Ubuntu 22.04/24.04  |
| pwndbg-lldb | - Python 3.12+ <br/>- LLDB 19+  | Experimental/early-stage support     |
| qemu-user   | QEMU 8.1+                       | vFile API is needed for vmmap        |
| qemu-system | QEMU 6.2+                       | Supported version since ubuntu 22.04 |

## How?

See [installation instructions](https://pwndbg.re/pwndbg/dev/setup).

## What can I do with that?

For further info about features/functionalities, see [FEATURES](https://github.com/pwndbg/pwndbg/blob/dev/FEATURES.md).

## Who?

Pwndbg is an open-source project, maintained by [many contributors](https://github.com/pwndbg/pwndbg/graphs/contributors)!

Pwndbg was originally created by [Zach Riggle](https://github.com/zachriggle), who is no longer with us. We want to thank Zach for all of his contributions to Pwndbg and the wider security community.

Want to help with development? Read [CONTRIBUTING](https://github.com/pwndbg/pwndbg/blob/dev/.github/CONTRIBUTING.md) or [join our Discord server][discord]!

## How to develop?
To run tests locally you can do this in docker image, after cloning repo run simply
```shell
docker compose run main ./tests.sh
```
Disclaimer - this won't work on apple silicon macs.

## Contact
If you have any questions not worthy of a [bug report](https://github.com/pwndbg/pwndbg/issues), feel free to ping
anybody on [Discord][discord] and ask away.

[discord]: https://discord.gg/x47DssnGwm
