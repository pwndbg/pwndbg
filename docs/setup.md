---
hide:
  - navigation
---

# Setup

There are multiple ways to install pwndbg, depending on whether you want to use it [with GDB](#installing-pwndbg-gdb), [with LLDB](#installing-pwndbg-lldb), use a [portable release](#download-the-portable-version), or install it [from source](#installing-from-source).

## Installing pwndbg-gdb
Install via curl/sh (Linux/macOS)
```{.bash .copy}
curl -qsL 'https://install.pwndbg.re' | sh -s -- -t pwndbg-gdb
```
Install via Homebrew (macOS)
```{.bash .copy}
brew install pwndbg/tap/pwndbg-gdb
```
Install via the Nix package manager (Linux/macOS)
```{.bash .copy}
nix shell github:pwndbg/pwndbg
```
### Through package manager
When installing with GDB, you may also download a package to install through your package manager of choice. Download the package from the [releases page](https://github.com/pwndbg/pwndbg/releases) and pick the appropriate download from the second table.


RPM-based Systems (CentOS/Alma/Rocky/RHEL):
```{.bash .copy}
dnf install ./pwndbg-2025.04.18.x86_64.rpm
```
DEB-based Systems (Debian/Ubuntu/Kali):
```{.bash .copy}
apt install ./pwndbg_2025.04.18_amd64.deb
```
Alpine:
```{.bash .copy}
apk add --allow-untrusted ./pwndbg_2025.04.18_x86_64.apk
```
Arch Linux:
```{.bash .copy}
pacman -U ./pwndbg-2025.04.18-1-x86_64.pkg.tar.zst
```

## Installing pwndbg-lldb
These installation methods provide the
```{.bash .copy}
pwndbg-lldb ./your-binary
```
command.

Install via curl/sh (Linux/macOS)
```{.bash .copy}
curl -qsL 'https://install.pwndbg.re' | sh -s -- -t pwndbg-lldb
```
Install via Homebrew (macOS)
```{.bash .copy}
brew install pwndbg/tap/pwndbg-lldb
```
Install via the Nix package manager (Linux/macOS):
```{.bash .copy}
nix shell github:pwndbg/pwndbg#pwndbg-lldb
```

## Download the Portable Version
You can download a portable release on the [pwndbg releases page](https://github.com/pwndbg/pwndbg/releases). There are seperate releases for GDB and LLDB. Use the first table to pick the appropriate download for your system architecture. You can then unpack the archive with:
```{.bash .copy}
tar -v -xf <archive-name>
```
And run pwndbg with
```bash
./pwndbg/bin/pwndbg
```
or
```
./pwndbg/bin/pwndbg-lldb
```
depending on which version you installed. You may add the appropriate file to your shell's PATH.
!!! warning ".gdbinit doesn't work for portable release"
    If you're running `./pwndbg/bin/pwndbg` from the portable release, it is a known limitation that pwndbg settings in your `.gdbinit` won't work (see [issue #2774](https://github.com/pwndbg/pwndbg/issues/2774)). Also, make sure not to source pwndbg in your gdbinit as it already happens automatically for portable releases (if this is the first time you're installing pwndbg, you don't need to worry about this).

## Installing from source
See the relevant section in DEVELOPING.md: [with GDB](https://github.com/pwndbg/pwndbg/blob/dev/DEVELOPING.md#install-from-source-gdb), [with LLDB](https://github.com/pwndbg/pwndbg/blob/dev/DEVELOPING.md#install-from-source-lldb).
