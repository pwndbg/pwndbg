---
hide:
  - navigation
---

# Setup

### Installing Pwndbg-LLDB
* Install via curl/sh (Linux/macOS)
```
curl -qsL 'https://install.pwndbg.re' | /bin/sh -s -- -t pwndbg-lldb
```
* Install via Homebrew (macOS)
```
brew install pwndbg/tap/pwndbg-lldb
```
* Install via the Nix package manager (Linux/macOS):
```shell
nix shell github:pwndbg/pwndbg#pwndbg-lldb
pwndbg-lldb ./your-binary
```
* Install from source [go here](https://github.com/pwndbg/pwndbg/blob/dev/DEVELOPING.md#install-from-source-lldb)

### Installing Pwndbg-GDB
* Install via curl/sh (Linux/macOS)
```
curl -qsL 'https://install.pwndbg.re' | /bin/sh -s -- -t pwndbg-gdb
```
* Install via Homebrew (macOS)
```
brew install pwndbg/tap/pwndbg-gdb
```
* Install via the Nix package manager (Linux/macOS)
```shell
nix shell github:pwndbg/pwndbg
pwndbg ./your-binary
```
* [Install via your distro’s package manager (apt, yum, dnf, apk, pacman)](https://pwndbg.re/pwndbg/latest/setup/#download-the-portable-version)
* [Install from source](https://github.com/pwndbg/pwndbg/blob/dev/DEVELOPING.md#install-from-source-gdb)

### Download the Portable Version:

> [!TIP]
> Download the proper version from the [Pwndbg releases page](https://github.com/pwndbg/pwndbg/releases).
> Choose the appropriate version for your system architecture.

### Installation Pwndbg-GDB on RPM-based Systems (CentOS/Alma/Rocky/RHEL):

```shell
dnf install ./pwndbg-2025.04.18.x86_64.rpm
# pwndbg
```

### Installation Pwndbg-GDB on DEB-based Systems (Debian/Ubuntu/Kali):

```shell
apt install ./pwndbg_2025.04.18_amd64.deb
# pwndbg
```

### Installation Pwndbg-GDB on Alpine:

```shell
apk add --allow-untrusted ./pwndbg_2025.04.18_x86_64.apk
# pwndbg
```

### Installation Pwndbg-GDB on Arch Linux:

```shell
pacman -U ./pwndbg-2025.04.18-1-x86_64.pkg.tar.zst
# pwndbg
```

### Generic Linux Installation:

```shell
tar -v -xf ./pwndbg_2025.04.18_x86_64-portable.tar.xz
# ./pwndbg/bin/pwndbg
```
