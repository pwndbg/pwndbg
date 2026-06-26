---
hide:
  - navigation
---

# Setup

There are multiple ways to install Pwndbg, depending on whether you want to use it [with GDB](#installing-pwndbg-gdb), [with LLDB](#installing-pwndbg-lldb), or install it [from source](#installing-from-source).

## Installing pwndbg-gdb

This will provide the `pwndbg` program. You can use it the same way you use `gdb`.

### Portable release
The install script will automatically fetch and install the portable release from [GitHub releases](https://github.com/pwndbg/pwndbg/releases).

=== "System install"
    Install the binary for all users of the system. This requires root permissions, and will invoke sudo.

    Install via curl/sh (Linux/macOS). 
    ```{.bash .copy}
    curl --proto '=https' --tlsv1.2 -LsSf 'https://install.pwndbg.re' | sh -s -- -t pwndbg-gdb
    ```
    Install via GNU wget/sh (Linux/macOS)
    ```{.bash .copy}
    wget --https-only --secure-protocol=TLSv1_2 -qO- 'https://install.pwndbg.re' | sh -s -- -t pwndbg-gdb
    ```
    Install via BusyBox wget/sh (Linux/macOS)
    ```{.bash .copy}
    wget -qO- 'https://install.pwndbg.re' | sh -s -- -t pwndbg-gdb
    ```
=== "User install"
    Install the binary for the current user. Root access not required.

    Install via curl/sh (Linux/macOS). 
    ```{.bash .copy}
    curl --proto '=https' --tlsv1.2 -LsSf 'https://install.pwndbg.re' | sh -s -- -t pwndbg-gdb -u
    ```
    Install via GNU wget/sh (Linux/macOS)
    ```{.bash .copy}
    wget --https-only --secure-protocol=TLSv1_2 -qO- 'https://install.pwndbg.re' | sh -s -- -t pwndbg-gdb -u
    ```
    Install via BusyBox wget/sh (Linux/macOS)
    ```{.bash .copy}
    wget -qO- 'https://install.pwndbg.re' | sh -s -- -t pwndbg-gdb -u
    ```

### Homebrew
Install via Homebrew (macOS)
```{.bash .copy}
brew install pwndbg/tap/pwndbg-gdb
```

### Nix
Install via the Nix package manager (Linux/macOS)
```{.bash .copy}
nix shell github:pwndbg/pwndbg
```
### Official Pwndbg packages
When installing with GDB, you may also download a package to install through your package manager of choice. Download the package from the [releases page](https://github.com/pwndbg/pwndbg/releases) and pick the appropriate download from the second table.

RPM-based Systems (CentOS/Alma/Rocky/RHEL):
```{.bash .copy}
dnf install ./pwndbg-2026.02.18.x86_64.rpm
```
DEB-based Systems (Debian/Ubuntu/Kali):
```{.bash .copy}
apt install ./pwndbg_2026.02.18_amd64.deb
```
Alpine:
```{.bash .copy}
apk add --allow-untrusted ./pwndbg_2026.02.18_x86_64.apk
```
Arch Linux:
```{.bash .copy}
pacman -U ./pwndbg-2026.02.18-1-x86_64.pkg.tar.zst
```
### Distro packages
You may want to install Pwndbg through your distribution's package manager. This installation method is **not officially supported** because we cannot control the versions of the python dependencies Pwndbg uses in this case. Please use any other installation method when reproducing bug reports (portable package is probably simplest in this case). If a bug reproduces with a distro package but not with any of the supported installation methods, please report it to the package maintainer; if the problem cannot be fixed, let us know and we will add it to a list of known issues below.

=== "Arch"
    ```{.bash .copy}
    sudo pacman -S pwndbg
    ```
    Pwndbg will now be available with the `pwndbg` and `pwndbg-lldb` commands.

=== "Gentoo"
    ```{.bash .copy}
    sudo emerge --ask dev-debug/pwndbg
    ```
    Pwndbg will now be available with the `pwndbg` and `pwndbg-lldb` commands.

----

## Installing pwndbg-lldb
These installation methods provide the
```{.bash .copy}
pwndbg-lldb ./your-binary
```
command.
### Portable release
Install via curl/sh (Linux/macOS)
=== "System install"
    ```{.bash .copy}
    curl --proto '=https' --tlsv1.2 -LsSf 'https://install.pwndbg.re' | sh -s -- -t pwndbg-lldb
    ```

=== "User install"
    ```{.bash .copy}
    curl --proto '=https' --tlsv1.2 -LsSf 'https://install.pwndbg.re' | sh -s -- -t pwndbg-lldb -u
    ```

### Homebrew
Install via Homebrew (macOS)
```{.bash .copy}
brew install pwndbg/tap/pwndbg-lldb
```

### Nix
Install via the Nix package manager (Linux/macOS):
```{.bash .copy}
nix shell github:pwndbg/pwndbg#pwndbg-lldb
```

## Manually install the Portable Version
You can download a portable release on the [Pwndbg releases page](https://github.com/pwndbg/pwndbg/releases). There are separate releases for GDB and LLDB. Use the first table to pick the appropriate download for your system architecture. You can then unpack the archive with:
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

### Removing Quarantine Flags (macOS)

When first setting up the portable version of Pwndbg in macOS, Gatekeeper will normally try to prevent
any code in the extracted files from running until the user explicitly allows each file to be run.
As we ship many files which would require this, the process of manually granting permission for each
one to be run can get quite tiresome.

In order to do this to all files at once, you may choose to run the following command, which removes
the quarantine flag from all extracted files at once:

```{.bash .copy}
xattr -rd com.apple.quarantine pwndbg
```

Assuming that the files were extracted to a folder called `pwndbg`.

## Installing from source

First things first, you need to have [uv installed](https://docs.astral.sh/uv/getting-started/installation/#standalone-installer) (and git and curl):
```{.bash .copy}
curl -LsSf https://astral.sh/uv/install.sh | sh
source $HOME/.local/bin/env
```

If you just want the most up-to-date Pwndbg, the simplest thing to do is just:
```{.bash .copy}
uv tool install git+https://github.com/pwndbg/pwndbg[gdb,lldb]
```
which gives you the `pwndbg` and `pwndbg-lldb` binaries. If you want to update, just re-run this command.

### I want to use my system GDB / LLDB

If you don't want Pwndbg to use our up-to-date packaged+patched [GDB and LLDB](https://github.com/pwndbg/pypi-for-pwndbg), but rather the GDB / LLDB from your system / package manager, you can install Pwndbg with:
```{.bash .copy}
# Assuming that your LLDB and GDB are compiled with the same python version :)
PY_VER=$(gdb -nx --batch -iex 'py import sysconfig; print(sysconfig.get_config_var("VERSION"))')
uv tool install --python=$PY_VER  git+https://github.com/pwndbg/pwndbg
```
To view supported GDB and LLDB versions and compiling GDB from source, see [these instructions](contributing/setup-pwndbg-dev.md#installing-pwndbg-from-source).

### System GDB, sourced from `~/.gdbinit`

If you want the "classic" setup, where you run the `gdb` binary and Pwndbg is sourced from `~/.gdbinit` you can do that like this:
```{.bash .copy}
PY_VER=$(gdb -nx --batch -iex 'py import sysconfig; print(sysconfig.get_config_var("VERSION"))')
uv tool install --python=$PY_VER  git+https://github.com/pwndbg/pwndbg
echo "source $(uv tool dir)/pwndbg/share/pwndbg/gdbinit.py" >> ~/.gdbinit
```

### Really from source

Running this:
```{.bash .copy}
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```
will get you the same setup as in [System GDB, sourced from `~/.gdbinit`](#system-gdb-sourced-from-gdbinit). You can update with `git pull`.

In general, if you have the repository cloned you can run the same commands as in the above sections, but replacing `git+https://github.com/pwndbg/pwndbg` with `.` (the current folder) and adding `--editable` so changes in the source are reflected in the installation.

## Setup for development

For getting setup for development, see [contributing/Installing Pwndbg from source](contributing/setup-pwndbg-dev.md#installing-pwndbg-from-source).

