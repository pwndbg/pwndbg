---
hide:
  - navigation
---

# Setup

There are multiple ways to install Pwndbg, depending on whether you want to use it [with GDB](#installing-pwndbg-gdb), [with LLDB](#installing-pwndbg-lldb), use a [portable release](#download-the-portable-version), or install it [from source](#installing-from-source).

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
### Official Pwndbg packages
When installing with GDB, you may also download a package to install through your package manager of choice. Download the package from the [releases page](https://github.com/pwndbg/pwndbg/releases) and pick the appropriate download from the second table.

RPM-based Systems (CentOS/Alma/Rocky/RHEL):
```{.bash .copy}
dnf install ./pwndbg-2025.05.30.x86_64.rpm
```
DEB-based Systems (Debian/Ubuntu/Kali):
```{.bash .copy}
apt install ./pwndbg_2025.05.30_amd64.deb
```
Alpine:
```{.bash .copy}
apk add --allow-untrusted ./pwndbg_2025.05.30_x86_64.apk
```
Arch Linux:
```{.bash .copy}
pacman -U ./pwndbg-2025.05.30-1-x86_64.pkg.tar.zst
```
### Distro packages
You may want to install Pwndbg through your distribution's package manager. This installation method is **not officially supported** because we cannot control the versions of the python dependencies Pwndbg uses in this case. Please use any other installation method when reproducing bug reports (portable package is probably simplest in this case). If a bug reproduces with a distro package but not with any of the supported installation methods, please report it to the package maintainer; if the problem cannot be fixed, let us know and we will add it to a list of known issues below.

=== "Arch"
    ```{.bash .copy}
    sudo pacman -S pwndbg
    ```
    You will also need to source Pwndbg from your `~/.gdbinit`. Add this line to the beginning of that file:
    ```{.bash .copy}
    source /usr/share/pwndbg/gdbinit.py
    ```
    Pwndbg will be started every time you invoke `gdb` now.

=== "Gentoo"
    ```{.bash .copy}
    sudo emerge --ask dev-debug/pwndbg
    ```

----

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
You can download a portable release on the [Pwndbg releases page](https://github.com/pwndbg/pwndbg/releases). There are seperate releases for GDB and LLDB. Use the first table to pick the appropriate download for your system architecture. You can then unpack the archive with:
```{.bash .copy}
tar -v -xf <archive-name>
```
And run Pwndbg with
```bash
./pwndbg/bin/pwndbg
```
or
```
./pwndbg/bin/pwndbg-lldb
```
depending on which version you installed. You may add the appropriate file to your shell's PATH.

## Installing from source
See [contributing/Installing Pwndbg from source](contributing/setup-pwndbg-dev.md#installing-pwndbg-from-source), you do not need the "The development environment" section.
