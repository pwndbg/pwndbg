![repository-open-graph](https://github.com/pwndbg/pwndbg/assets/150354584/77b2e438-898f-416f-a989-4bef30759627)
# pwndbg

[![license](https://img.shields.io/github/license/mashape/apistatus.svg?maxAge=2592000)](https://choosealicense.com/licenses/mit/)
[![Tests](https://github.com/pwndbg/pwndbg/actions/workflows/tests.yml/badge.svg?branch=dev&event=push)](https://github.com/pwndbg/pwndbg/actions/workflows/tests.yml)
[![codecov.io](https://codecov.io/github/pwndbg/pwndbg/branch/dev/badge.svg?token=i1cBPFVCav)](https://app.codecov.io/github/pwndbg/pwndbg/tree/dev)
[![Discord](https://img.shields.io/discord/843809097920413717?label=Discord&style=plastic)](https://discord.gg/x47DssnGwm)

`pwndbg` (/paʊnˈdiˌbʌɡ/) is a GDB and LLDB plug-in that makes debugging suck less,
with a focus on features needed by low-level software developers, hardware hackers,
reverse-engineers and exploit developers.

It has a boatload of features, see our [Features page](https://pwndbg.re/pwndbg/latest/features/)
and [CHEATSHEET][CHEATSHEET] (feel free to print it!). If you have any questions you may read the
[documentation](https://pwndbg.re/pwndbg/latest/) or asks us in our [Discord server](https://discord.gg/x47DssnGwm).

[CHEATSHEET]: https://pwndbg.re/pwndbg/dev/CHEATSHEET.pdf

## Why?

Vanilla GDB and LLDB are terrible to use for reverse engineering and exploit development.
Typing `x/30gx $rsp` or navigating cumbersome LLDB commands is not fun and often provides
minimal information. The year is 2025, and core debuggers still lack many user-friendly
features such as a robust hexdump command. WinDbg users are completely lost when they
occasionally need to bump into GDB or LLDB.

Pwndbg is a Python module which can be loaded into GDB or run as a REPL interface for LLDB.
It provides a suite of utilities and enhancements that fill the gaps left by these debuggers,
smoothing out rough edges and making them more user-friendly.

## Installation

See [installation instructions](https://pwndbg.re/pwndbg/latest/setup).

## What about ...?

Many past ([gdbinit][gdbinit], [PEDA][PEDA]) and present projects ([GEF][GEF],
[bata24/GEF][bata24/GEF]) offer great features, but are hard to extend and are packaged
as large single files ([103KB][gdbinit2], [195KB][peda.py], [423KB][gef.py],
[4.12MB][bata24/gef.py]). Pwndbg aims to replace them with a faster, cleaner, and
more robust implementation.

[gdbinit]: https://github.com/gdbinit/Gdbinit
[gdbinit2]: https://github.com/gdbinit/Gdbinit/blob/master/gdbinit
[PEDA]: https://github.com/longld/peda
[peda.py]: https://github.com/longld/peda/blob/master/peda.py
[GEF]: https://github.com/hugsy/gef
[gef.py]: https://github.com/hugsy/gef/blob/main/gef.py
[bata24/GEF]: https://github.com/bata24/gef
[bata24/gef.py]: https://github.com/bata24/gef/blob/dev/gef.py

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
> The LLDB implementation in pwndbg is still in early-stage and may contain bugs or limitations.<br/>
> Known issues are tracked in [GitHub Issues][lldb_tracker].
>
> If you encounter any problems, feel free to report them or discuss on our [Discord server](https://discord.gg/x47DssnGwm).

[lldb_tracker]: https://github.com/pwndbg/pwndbg/issues?q=is%3Aissue%20state%3Aopen%20label%3A%22LLDB%20Port%22

### Compatibility Table
| Feature     | Supported Version               | Notes                                |
|-------------|---------------------------------|--------------------------------------|
| pwndbg-gdb  | - Python 3.10+ <br/>- GDB 12.1+ | Battle-tested on Ubuntu 22.04/24.04  |
| pwndbg-lldb | - Python 3.12+ <br/>- LLDB 19+  | Experimental/early-stage support     |
| qemu-user   | QEMU 8.1+                       | vFile API is needed for vmmap        |
| qemu-system | QEMU 6.2+                       | Supported version since ubuntu 22.04 |


## Contributing
Pull requests are welcome ❤️. Check out the [Contributing Guide](https://pwndbg.re/pwndbg/dev/contributing/).

## Acknowledgements
Pwndbg was originally created by [Zach Riggle](https://github.com/zachriggle), who is no longer with us. We want to thank Zach for all of his contributions to pwndbg and the wider security community.
