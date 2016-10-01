# pwndbg [![Build Status](https://travis-ci.org/pwndbg/pwndbg.svg?branch=master)](https://travis-ci.org/pwndbg/pwndbg) [![license](https://img.shields.io/github/license/mashape/apistatus.svg?maxAge=2592000)]()
### /poʊndbæg/
#### noun
1. a collection of python that makes debugging with gdb suck less  
2. a [PEDA](https://github.com/longld/peda) replacement

[![Pwndbg](/caps/best.png?raw=true "Pwndbg")]

## Why?

Vanilla GDB is terrible to use for reverse engineering and exploit development. Typing `x/g30x $esp` is not fun, and does not  confer much information.  The year is 2016 and GDB still lacks a hexdump command.  GDB's syntax is arcane and difficult to approach.  Windbg users are completely lost when they occasionally need to bump into GDB.

## What?

Pwndbg is a Python module which is loaded directly into GDB, and provides a suite of utilities and crutches to hack around all of the cruft that is GDB and smooth out the rough edges.

Many other projects from the past (e.g., [gdbinit][gdbinit], [PEDA][PEDA]) and present (e.g. [GEF][GEF]) exist to fill some these gaps.  Unfortunately, they're all either unmaintained, unmaintainable, or not well suited to easily navigating the code to hack in new features (respectively).

Pwndbg exists not only to replace all of its predecessors, but also to have a clean implementation that runs quickly and is resilient against all the weird corner cases that come up.

[gdbinit]: https://github.com/gdbinit/Gdbinit
[PEDA]: https://github.com/longld/peda
[GEF]: https://github.com/hugsy/gef

## How?

Installation is straightforward.  Pwndbg is best supported on Ubuntu 14.04 with GDB 7.7, and Ubuntu 16.04 with GDB 7.11.  

```shell
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

If you use any other Linux distribution, we recommend using the latest available GDB built from source.  Be sure to pass `--with-python=/path/to/python` to `configure`.

## Who?

Most of Pwndbg was written by [Zach Riggle](https://twitter.com/ebeip90), with [many other contributors](https://github.com/pwndbg/pwndbg/graphs/contributors) offering up patches via Pull Requests.

## Contact
If you have any questions not worthy of a [bug report](https://github.com/pwndbg/pwndbg/issues), feel free to ping
at [`ebeip90` on Freenode](irc://irc.freenode.net/pwndbg) and ask away.
Click [here](https://kiwiirc.com/client/irc.freenode.net/pwndbg) to connect.
