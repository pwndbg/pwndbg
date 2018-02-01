# pwndbg [![Build Status](https://travis-ci.org/pwndbg/pwndbg.svg?branch=dev)](https://travis-ci.org/pwndbg/pwndbg) [![license](https://img.shields.io/github/license/mashape/apistatus.svg?maxAge=2592000)](https://github.com/pwndbg/pwndbg/blob/dev/LICENSE.md) [![Py2&3](https://img.shields.io/badge/Python-2%20%26%203-green.svg)]() [![IRC](https://img.shields.io/badge/freenode-%23pwndbg-red.svg)](https://webchat.freenode.net/?channels=#pwndbg)

`pwndbg` (/poʊndbæg/) is a GDB plug-in that makes debugging with GDB suck less, with a focus on features needed by low-level software developers, hardware hackers, reverse-engineers and exploit developers.

It has a boatload of features, see [FEATURES.md](FEATURES.md).

## Why?

Vanilla GDB is terrible to use for reverse engineering and exploit development. Typing `x/g30x $esp` is not fun, and does not  confer much information.  The year is 2017 and GDB still lacks a hexdump command.  GDB's syntax is arcane and difficult to approach.  Windbg users are completely lost when they occasionally need to bump into GDB.

## What?

Pwndbg is a Python module which is loaded directly into GDB, and provides a suite of utilities and crutches to hack around all of the cruft that is GDB and smooth out the rough edges.

Many other projects from the past (e.g., [gdbinit][gdbinit], [PEDA][PEDA]) and present (e.g. [GEF][GEF]) exist to fill some these gaps.  Each provides an excellent experience and great features -- but they're difficult to extend (some are unmaintained, and all are a single [100KB][gdbinit2], [200KB][peda.py], or [300KB][gef.py] file (respectively)).

Pwndbg exists not only to replace all of its predecessors, but also to have a clean implementation that runs quickly and is resilient against all the weird corner cases that come up.

[gdbinit]: https://github.com/gdbinit/Gdbinit
[gdbinit2]: https://github.com/gdbinit/Gdbinit/blob/master/gdbinit

[PEDA]: https://github.com/longld/peda
[peda.py]: https://github.com/longld/peda/blob/master/peda.py

[GEF]: https://github.com/hugsy/gef
[gef.py]: https://github.com/hugsy/gef/blob/master/gef.py

## How?

Installation is straightforward.  Pwndbg is best supported on Ubuntu 14.04 with GDB 7.7, and Ubuntu 16.04 with GDB 7.11.  

```shell
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

If you use any other Linux distribution, we recommend using the latest available GDB built from source.  Be sure to pass `--with-python=/path/to/python` to `configure`.

## What can I do with that?

For further info about features/functionalities, see [FEATURES](FEATURES.md).

## Who?

Most of Pwndbg was written by [Zach Riggle](https://twitter.com/ebeip90), with [many other contributors](https://github.com/pwndbg/pwndbg/graphs/contributors) offering up patches via Pull Requests.

Want to help with development? Read [CONTRIBUTING](.github/CONTRIBUTING.md).

## Contact
If you have any questions not worthy of a [bug report](https://github.com/pwndbg/pwndbg/issues), feel free to ping
[`ebeip90` at #pwndbg on Freenode](irc://irc.freenode.net/pwndbg) and ask away.
Click [here](https://kiwiirc.com/client/irc.freenode.net/pwndbg) to connect.
