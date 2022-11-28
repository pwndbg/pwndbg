# pwndbg

[![license](https://img.shields.io/github/license/mashape/apistatus.svg?maxAge=2592000)](https://choosealicense.com/licenses/mit/)
[![Unit tests](https://github.com/pwndbg/pwndbg/actions/workflows/tests.yml/badge.svg?branch=dev&event=push)](https://github.com/pwndbg/pwndbg/actions/workflows/tests.yml)
[![Discord](https://img.shields.io/discord/843809097920413717?label=Discord&style=plastic)](https://discord.gg/x47DssnGwm)

`pwndbg` (/poʊndbæg/) is a GDB plug-in that makes debugging with GDB suck less, with a focus on features needed by low-level software developers, hardware hackers, reverse-engineers and exploit developers.

It has a boatload of features, see [FEATURES.md](FEATURES.md).

## Why?

Vanilla GDB is terrible to use for reverse engineering and exploit development. Typing `x/g30x $esp` is not fun, and does not  confer much information.  The year is 2022 and GDB still lacks a real hexdump command!  GDB's syntax is arcane and difficult to approach.  Windbg users are completely lost when they occasionally need to bump into GDB.

## What?

Pwndbg is a Python module which is loaded directly into GDB, and provides a suite of utilities and crutches to hack around all of the cruft that is GDB and smooth out the rough edges.

Many other projects from the past (e.g., [gdbinit][gdbinit], [PEDA][PEDA]) and present (e.g. [GEF][GEF]) exist to fill some these gaps.  Each provides an excellent experience and great features -- but they're difficult to extend (some are unmaintained, and all are a single [100KB][gdbinit2], [200KB][peda.py], or [363KB][gef.py] file (respectively)).

Pwndbg exists not only to replace all of its predecessors, but also to have a clean implementation that runs quickly and is resilient against all the weird corner cases that come up.  It also comes batteries-included, so all of its features are available if you run `setup.sh`.

[gdbinit]: https://github.com/gdbinit/Gdbinit
[gdbinit2]: https://github.com/gdbinit/Gdbinit/blob/master/gdbinit

[PEDA]: https://github.com/longld/peda
[peda.py]: https://github.com/longld/peda/blob/master/peda.py

[GEF]: https://github.com/hugsy/gef
[gef.py]: https://github.com/hugsy/gef/blob/master/gef.py

## How?

Installation is straightforward:

```shell
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

Pwndbg is supported on Ubuntu 18.04, 20.04, and 22.04 with GDB 8.1 and later. We do not test on any older versions of Ubuntu, so `pwndbg` may not work on these versions. We may accept pull requests fixing issues in older versions on a case by case basis, please discuss this with us on [Discord](https://discord.gg/x47DssnGwm) first. You can also always checkout an older version of `pwndbg` from around the time the Ubuntu version you're interested in was still supported by Canonical, or you can attempt to build a newer version of GDB from source.

Other Linux distributions are also supported via `setup.sh`, including:

* Debian-based OSes (via apt-get)
* Fedora and Red Hat (via dnf)
* Clear (via swiped)
* OpenSUSE LEAP (via zypper)
* Arch and Manjaro (via community AUR packages)
* Void (via xbps)
* Gentoo (via emerge)

If you use any Linux distribution other than Ubuntu, we recommend using the [latest available GDB](https://www.gnu.org/software/gdb/download/) built from source. You can build it as:
```
cd <gdb-sources-dir>
mkdir build
cd build
../configure --disable-nls --disable-werror --with-system-readline --with-python=`which python3` --with-system-gdbinit=/etc/gdb/gdbinit --enable-targets=all
make -j7
```

## What can I do with that?

For further info about features/functionalities, see [FEATURES](FEATURES.md).

## Who?

Pwndbg is an open-source project, written and maintained by [many contributors](https://github.com/pwndbg/pwndbg/graphs/contributors)!

Want to help with development? Read [CONTRIBUTING](.github/CONTRIBUTING.md) or [join our Discord server](https://discord.gg/x47DssnGwm)!

## How to develop?
To run tests locally you can do this in docker image, after cloning repo run simply
```shell
docker-compose run main ./tests.sh 
```
Disclaimer - this won't work on apple silicon macs.

## Contact
If you have any questions not worthy of a [bug report](https://github.com/pwndbg/pwndbg/issues), feel free to ping
anybody on [Discord](https://discord.gg/x47DssnGwm) and ask away.
