![repository-open-graph](https://github.com/pwndbg/pwndbg/assets/150354584/77b2e438-898f-416f-a989-4bef30759627)
# pwndbg

[![license](https://img.shields.io/github/license/mashape/apistatus.svg?maxAge=2592000)](https://choosealicense.com/licenses/mit/)
[![Unit tests](https://github.com/pwndbg/pwndbg/actions/workflows/tests.yml/badge.svg?branch=dev&event=push)](https://github.com/pwndbg/pwndbg/actions/workflows/tests.yml)
[![codecov.io](https://codecov.io/github/pwndbg/pwndbg/branch/dev/badge.svg?token=i1cBPFVCav)](https://app.codecov.io/github/pwndbg/pwndbg/tree/dev)
[![Discord](https://img.shields.io/discord/843809097920413717?label=Discord&style=plastic)](https://discord.gg/x47DssnGwm)

`pwndbg` (/paʊnˈdiˌbʌɡ/) is a GDB and LLDB plug-in that makes debugging suck less, 
with a focus on features needed by low-level software developers, hardware hackers, 
reverse-engineers and exploit developers.

It has a boatload of features, see [FEATURES.md](FEATURES.md) and [CHEATSHEET][CHEATSHEET] 
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

For a portable version with no external dependencies, scroll down for the [Portable Installation](#portable-installation) section.

### Installing LLDB

* Install via the Nix package manager (you can use Nix on any distribution):
```shell
nix shell github:pwndbg/pwndbg#pwndbg-lldb
pwndbg-lldb ./your-binary
```
* Or download portable version with no external dependencies, scroll down for the [Portable Installation](#portable-installation) section
* ~~Or install from source, instructions below.~~ (not supported)

### Installing GDB

* Install via the Nix package manager (you can use Nix on any distribution):
```shell
nix shell github:pwndbg/pwndbg
pwndbg ./your-binary
```
* Or download portable version with no external dependencies, scroll down for the [Portable Installation](#portable-installation) section

* Or install from source, instructions below.
<details>
  <summary>Click here to expand instructions</summary>

Installation from source is straightforward:
```shell
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

Pwndbg is supported on Ubuntu 22.04, and 24.04 with GDB 12.1 and later. We do not test 
on any older versions of Ubuntu, so `pwndbg` may not work on these versions.
- For Ubuntu 20.04 use the [2024.08.29 release](https://github.com/pwndbg/pwndbg/releases/tag/2024.08.29)
- For Ubuntu 18.04 use the [2023.07.17: ubuntu18.04-final release](https://github.com/pwndbg/pwndbg/releases/tag/2023.07.17)

We may accept pull requests fixing issues in older versions on a case by case basis, 
please discuss this with us on [Discord][discord] first. You can also always checkout 
an older version of `pwndbg` from around the time the Ubuntu version you're interested
in was still supported by Canonical, or you can attempt to build a newer version of GDB from source.

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
</details>

## Portable Installation:

The portable version includes all necessary dependencies and should work without the need to install additional packages.

### Download the Portable Version:

Download the portable version from the [Pwndbg releases page](https://github.com/pwndbg/pwndbg/releases) by selecting the desired version.

**Note:** For LLDB, only the tarball version is available.

Make sure to select the correct file for your operating system and architecture:
- **Linux (x86_64, armv7l, aarch64, riscv64):**
  - `pwndbg_2024.08.29_amd64.tar.xz` (x86_64 for GDB)
  - `pwndbg_2024.08.29_armv7.tar.xz` (armv7l for GDB)
  - `pwndbg_2024.08.29_arm64.tar.xz` (aarch64 for GDB)
  - `pwndbg_2024.08.29_riscv64.tar.xz` (riscv64 for GDB)
  - `pwndbg-lldb_2024.08.29_amd64.tar.xz` (x86_64 for LLDB)
  - `pwndbg-lldb_2024.08.29_armv7.tar.xz` (armv7l for LLDB)
  - `pwndbg-lldb_2024.08.29_arm64.tar.xz` (aarch64 for LLDB)
  - `pwndbg-lldb_2024.08.29_riscv64.tar.xz` (riscv64 for LLDB)

- **macOS (amd64, arm64):**
  - `pwndbg-lldb_2024.08.29_macos_amd64.tar.xz` (macOS, Intel/AMD CPUs, for LLDB)
  - `pwndbg-lldb_2024.08.29_macos_arm64.tar.xz` (macOS, Apple Silicon/M1/M2/M*, for LLDB)
  - `pwndbg_2024.08.29_macos_amd64.tar.xz` (macOS, Intel/AMD CPUs for GDB)
  - `pwndbg_2024.08.29_macos_amd64.tar.xz` (macOS, Apple Silicon/M1/M2/M*, for GDB via **Rosseta emulation**)


#### Instructions:
- Portable tarball:
```shell
tar -v -xf ./pwndbg_2024.08.29_amd64.tar.xz
# ./pwndbg/bin/pwndbg
# or ./pwndbg/bin/pwndbg-lldb
```
- Installation on RPM-based Systems (CentOS/Alma/Rocky/RHEL):
```shell
dnf install ./pwndbg-2024.08.29.x86_64.rpm
# pwndbg
# and/or pwndbg-lldb
```

- Installation on DEB-based Systems (Debian/Ubuntu/Kali):
```shell
apt install ./pwndbg_2024.08.29_amd64.deb
# pwndbg
# and/or pwndbg-lldb
```

- Installation on Alpine:
```shell
apk add --allow-untrusted ./pwndbg_2024.08.29_x86_64.apk
# pwndbg
# and/or pwndbg-lldb
```

- Installation on Arch Linux:
```shell
pacman -U ./pwndbg-2024.08.29-1-x86_64.pkg.tar.zst
# pwndbg
# and/or pwndbg-lldb
```

## What can I do with that?

For further info about features/functionalities, see [FEATURES](FEATURES.md).

## Who?

Pwndbg is an open-source project, maintained by [many contributors](https://github.com/pwndbg/pwndbg/graphs/contributors)!

Pwndbg was originally created by [Zach Riggle](https://github.com/zachriggle), who is no longer with us. We want to thank Zach for all of his contributions to Pwndbg and the wider security community.

Want to help with development? Read [CONTRIBUTING](.github/CONTRIBUTING.md) or [join our Discord server][discord]!

## How to develop?
To run tests locally you can do this in docker image, after cloning repo run simply
```shell
docker-compose run main ./tests.sh
```
Disclaimer - this won't work on apple silicon macs.

## Contact
If you have any questions not worthy of a [bug report](https://github.com/pwndbg/pwndbg/issues), feel free to ping
anybody on [Discord][discord] and ask away.

[discord]: https://discord.gg/x47DssnGwm
