![repository-open-graph](https://github.com/pwndbg/pwndbg/assets/150354584/77b2e438-898f-416f-a989-4bef30759627)
# pwndbg

[![license](https://img.shields.io/github/license/mashape/apistatus.svg?maxAge=2592000)](https://choosealicense.com/licenses/mit/)
[![Unit tests](https://github.com/pwndbg/pwndbg/actions/workflows/tests.yml/badge.svg?branch=dev&event=push)](https://github.com/pwndbg/pwndbg/actions/workflows/tests.yml)
[![codecov.io](https://codecov.io/github/pwndbg/pwndbg/branch/dev/badge.svg?token=i1cBPFVCav)](https://app.codecov.io/github/pwndbg/pwndbg/tree/dev)
[![Discord](https://img.shields.io/discord/843809097920413717?label=Discord&style=plastic)](https://discord.gg/x47DssnGwm)

Pwndbg is a GDB and LLDB plugin for low-level debugging, reverse engineering and exploit development.

📖 [FEATURES](https://github.com/pwndbg/pwndbg/blob/dev/FEATURES.md)

📜 [CHEATSHEET][CHEATSHEET]

[CHEATSHEET]: https://drive.google.com/file/d/16t9MV8KTFXK7oX_CzXhmDdaVnjT8IYM4/view?usp=drive_link

## ❤️ Community & Contributions

Pwndbg is an open-source project, maintained by [many contributors](https://github.com/pwndbg/pwndbg/graphs/contributors)!

Pwndbg was originally created by [Zach Riggle](https://github.com/zachriggle), who is no longer with us. We want to thank Zach for all of his contributions to Pwndbg and the wider security community.

Want to contribute? Read [CONTRIBUTING](https://github.com/pwndbg/pwndbg/blob/dev/.github/CONTRIBUTING.md) guide and join our [Discord](https://discord.gg/x47DssnGwm)!

Please consider supporting the project by [sponsoring](https://github.com/sponsors/pwndbg) it.

## What is pwndbg?

Pwndbg is a Python module which is loaded directly into GDB or LLDB*. It provides a suite 
of utilities and enhancements that fill the gaps left by these debuggers, smoothing out 
rough edges and making them more user-friendly.

Simply run `setup.sh` to get started.

## Installation

Download a portable version from the [Pwndbg releases page](https://github.com/pwndbg/pwndbg/releases) by selecting the desired version.

<details>

**Note:** For LLDB, only the tarball version is available.

Make sure to select the correct file for your operating system and architecture:
- **Linux (x86_64, armv7l, aarch64, riscv64):**
  - `pwndbg_2025.02.19_amd64.tar.xz` (x86_64 for GDB)
  - `pwndbg_2025.02.19_armv7.tar.xz` (armv7l for GDB)
  - `pwndbg_2025.02.19_arm64.tar.xz` (aarch64 for GDB)
  - `pwndbg_2025.02.19_riscv64.tar.xz` (riscv64 for GDB)
  - `pwndbg-lldb_2025.02.19_amd64.tar.xz` (x86_64 for LLDB)
  - `pwndbg-lldb_2025.02.19_armv7.tar.xz` (armv7l for LLDB)
  - `pwndbg-lldb_2025.02.19_arm64.tar.xz` (aarch64 for LLDB)
  - `pwndbg-lldb_2025.02.19_riscv64.tar.xz` (riscv64 for LLDB)

- **macOS (amd64, arm64):**
  - `pwndbg-lldb_2025.02.19_macos_amd64.tar.xz` (macOS, Intel/AMD CPUs, for LLDB)
  - `pwndbg-lldb_2025.02.19_macos_arm64.tar.xz` (macOS, Apple Silicon/M1/M2/M*, for LLDB)
  - `pwndbg_2025.02.19_macos_amd64.tar.xz` (macOS, Intel/AMD CPUs for GDB)
  - `pwndbg_2025.02.19_macos_amd64.tar.xz` (macOS, Apple Silicon/M1/M2/M*, for GDB via **Rosseta emulation**)

- Portable tarball:
```shell
tar -v -xf ./pwndbg_2025.02.19_amd64.tar.xz
# ./pwndbg/bin/pwndbg
# or ./pwndbg/bin/pwndbg-lldb
```
- Installation on RPM-based Systems (CentOS/Alma/Rocky/RHEL):
```shell
dnf install ./pwndbg-2025.02.19.x86_64.rpm
# pwndbg
# and/or pwndbg-lldb
```

- Installation on DEB-based Systems (Debian/Ubuntu/Kali):
```shell
apt install ./pwndbg_2025.02.19_amd64.deb
# pwndbg
# and/or pwndbg-lldb
```

- Installation on Alpine:
```shell
apk add --allow-untrusted ./pwndbg_2025.02.19_x86_64.apk
# pwndbg
# and/or pwndbg-lldb
```

- Installation on Arch Linux:
```shell
pacman -U ./pwndbg-2025.02.19-1-x86_64.pkg.tar.zst
# pwndbg
# and/or pwndbg-lldb
```

### Installing LLDB

* Install via the Nix package manager (you can use Nix on any distribution):
```shell
nix shell github:pwndbg/pwndbg#pwndbg-lldb
pwndbg-lldb ./your-binary
```

### Installing GDB

* Install via the Nix package manager (you can use Nix on any distribution):
```shell
nix shell github:pwndbg/pwndbg
pwndbg ./your-binary
```

</details>


Or install from source, instructions below.

Installation from source is straightforward:
```shell
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```

<details>

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

## Developing

To run tests locally you can do this in docker image, after cloning repo run simply
```shell
docker compose run main ./tests.sh
```
Disclaimer - this won't work on apple silicon macs.

## When to use GDB or LLDB?

Pwndbg supports both GDB and LLDB, and each debugger has its own strengths. 
<details><summary>Here's a quick guide to help you decide which one to use:</summary>

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

</details>