
## Quick start
Installation from source is straightforward:

```shell
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```
## Install on Linux distributions
Nix package manager (you can use Nix on any distribution):
```shell
nix shell github:pwndbg/pwndbg
pwndbg ./your-binary
```

Pwndbg is supported on Ubuntu 22.04, and 24.04 with GDB 12.1 and later. We do not test on any older versions of Ubuntu, so `pwndbg` may not work on these versions (for Ubuntu 18.04 use the [2023.07.17: ubuntu18.04-final release](https://github.com/pwndbg/pwndbg/releases/tag/2023.07.17)). We may accept pull requests fixing issues in older versions on a case by case basis, please discuss this with us on [Discord](https://discord.gg/x47DssnGwm) first. You can also always checkout an older version of `pwndbg` from around the time the Ubuntu version you're interested in was still supported by Canonical, or you can attempt to build a newer version of GDB from source.

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

## Portable Installation from package

The portable version includes all necessary dependencies and should work without the need to install additional packages.

### Download the Portable Version:

Download the portable version from the [Pwndbg releases page](https://github.com/pwndbg/pwndbg/releases) by selecting the desired version.
Choose the appropriate version for your system architecture (x86_64, armv7l, aarch64, riscv64).

### Installation on RPM-based Systems (CentOS/Alma/Rocky/RHEL):

```shell
dnf install ./pwndbg-2024.08.29.x86_64.rpm
# pwndbg
```

### Installation on DEB-based Systems (Debian/Ubuntu/Kali):

```shell
apt install ./pwndbg_2024.08.29_amd64.deb
# pwndbg
```

### Installation on Alpine:

```shell
apk add --allow-untrusted ./pwndbg_2024.08.29_x86_64.apk
# pwndbg
```

### Installation on Arch Linux:

```shell
pacman -U ./pwndbg-2024.08.29-1-x86_64.pkg.tar.zst
# pwndbg
```

### Generic Linux Installation:

```shell
tar -v -xf ./pwndbg_2024.08.29_amd64.tar.xz
# ./pwndbg/bin/pwndbg
```
