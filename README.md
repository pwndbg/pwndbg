![repository-open-graph](https://github.com/pwndbg/pwndbg/assets/150354584/77b2e438-898f-416f-a989-4bef30759627)
# pwndbg

[![license](https://img.shields.io/github/license/mashape/apistatus.svg?maxAge=2592000)](https://choosealicense.com/licenses/mit/)
[![Unit tests](https://github.com/pwndbg/pwndbg/actions/workflows/tests.yml/badge.svg?branch=dev&event=push)](https://github.com/pwndbg/pwndbg/actions/workflows/tests.yml)
[![codecov.io](https://codecov.io/github/pwndbg/pwndbg/graph/badge.svg?token=i1cBPFVCav)](https://codecov.io/github/pwndbg/pwndbg?branch=dev)
[![Discord](https://img.shields.io/discord/843809097920413717?label=Discord&style=plastic)](https://discord.gg/x47DssnGwm)

`pwndbg` (/paʊnˈdiˌbʌɡ/) is a GDB plug-in that makes debugging with GDB suck less, with a focus on features needed by low-level software developers, hardware hackers, reverse-engineers and exploit developers.

It has a boatload of features, see [FEATURES.md](FEATURES.md) and [CHEATSHEET](https://drive.google.com/file/d/16t9MV8KTFXK7oX_CzXhmDdaVnjT8IYM4/view?usp=drive_link) (feel free to print it!).

## Why?

Vanilla GDB is terrible to use for reverse engineering and exploit development. Typing `x/g30x $esp` is not fun, and does not  confer much information.  The year is 2024 and GDB still lacks a real hexdump command!  GDB's syntax is arcane and difficult to approach.  Windbg users are completely lost when they occasionally need to bump into GDB.

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

For a portable version with no external dependencies, scroll down for the [Portable Installation](#portable-installation) section.

Installation from source is straightforward:

```shell
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

Or install via the Nix package manager (you can use Nix on any distribution):
```shell
nix shell github:pwndbg/pwndbg
pwndbg ./your-binary
```

Pwndbg is supported on Ubuntu 20.04, and 22.04 with GDB 9.2 and later. We do not test on any older versions of Ubuntu, so `pwndbg` may not work on these versions (for Ubuntu 18.04 use the [2023.07.17: ubuntu18.04-final release](https://github.com/pwndbg/pwndbg/releases/tag/2023.07.17)). We may accept pull requests fixing issues in older versions on a case by case basis, please discuss this with us on [Discord](https://discord.gg/x47DssnGwm) first. You can also always checkout an older version of `pwndbg` from around the time the Ubuntu version you're interested in was still supported by Canonical, or you can attempt to build a newer version of GDB from source.

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
mkdir build && cd build
sudo apt install libgmp-dev libmpfr-dev libreadline-dev texinfo  # required by build
../configure --disable-nls --disable-werror --with-system-readline --with-python=`which python3` --with-system-gdbinit=/etc/gdb/gdbinit --enable-targets=all
make -j7
```

## Portable Installation:

The portable version includes all necessary dependencies and should work without the need to install additional packages.

### Download the Portable Version:

Download the portable version from the [Pwndbg releases page](https://github.com/pwndbg/pwndbg/releases) by selecting the desired version.
Choose the appropriate version for your system architecture (x86_64 or aarch64).

### Installation on RPM-based Systems (CentOS/Alma/Rocky/RHEL):

```shell
dnf install ./pwndbg-2023.07.17.x86_64.rpm
# pwndbg
```

### Installation on DEB-based Systems (Debian/Ubuntu/Kali):

```shell
apt install ./pwndbg_2023.07.17_amd64.deb
# pwndbg
```

### Installation on Alpine:

```shell
apk add --allow-untrusted ./pwndbg_2023.07.17_x86_64.apk
# pwndbg
```

### Installation on Arch Linux:

```shell
pacman -U ./pwndbg-2023.07.17-1-x86_64.pkg.tar.zst
# pwndbg
```

### Generic Linux Installation:

```shell
tar -v -xf ./pwndbg_2023.07.17_amd64.tar.gz
# ./pwndbg/bin/pwndbg
```

## What can I do with that?

For further info about features/functionalities, see [FEATURES](FEATURES.md).

## Who?

Pwndbg is an open-source project, maintained by [many contributors](https://github.com/pwndbg/pwndbg/graphs/contributors)!

Pwndbg was originally created by [Zach Riggle](https://github.com/zachriggle), who is no longer with us. We want to thank Zach for all of his contributions to Pwndbg and the wider security community.

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

