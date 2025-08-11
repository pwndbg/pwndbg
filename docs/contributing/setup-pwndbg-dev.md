# Setup Pwndbg for Development

## Installing Pwndbg from source

Run the following:
```{.bash .copy}
git clone https://github.com/pwndbg/pwndbg
cd pwndbg
./setup.sh
```
Officially supported is Ubuntu 22.04 and later, but the setup script also supports the following distributions:

* Debian-based OSes (via apt-get)
* Fedora and Red Hat (via dnf)
* Clear (via swiped)
* OpenSUSE LEAP (via zypper)
* Arch and Manjaro (via community AUR packages)
* Void (via xbps)
* Gentoo (via emerge)

!!! tip
    If you have an older ubuntu version you may still use Pwndbg:

    - for Ubuntu 20.04 use the [2024.08.29 release](https://github.com/pwndbg/pwndbg/releases/tag/2024.08.29)
    - for Ubuntu 18.04 use the [2023.07.17: ubuntu18.04-final release](https://github.com/pwndbg/pwndbg/releases/tag/2023.07.17)

    however if you wish to contribute, it is recommended you upgrade your distribution.

### Running with GDB
Pwndbg requires GDB 12.1 or later. If the GDB version your distro provides is too old, [build GDB from source](https://sourceware.org/gdb/wiki/BuildingNatively):
```{.bash .copy}
sudo apt install libgmp-dev libmpfr-dev libreadline-dev texinfo  # required by build
git clone git://sourceware.org/git/binutils-gdb.git
mkdir gdb-build
cd gdb-build
../binutils-gdb/configure --enable-option-checking --disable-nls --disable-werror --with-system-readline --with-python=$(which python3) --with-system-gdbinit=/etc/gdb/gdbinit --enable-targets=all --disable-binutils --disable-ld --disable-gold --disable-gas --disable-sim --disable-gprof
make -j $(nproc)
```
Since the `./setup.sh` script made it so you source Pwndbg from your `~/.gdbinit`, Pwndbg will start up automatically any time you run `gdb`.

### Running with LLDB
Pwndbg requires LLDB 19 or later. You can get it like this on Ubuntu 24.04:
```{.bash .copy}
sudo apt install -y lldb-19 liblldb-19-dev
```
but it will be added to your PATH as `lldb-19` so you should either alias it or export it in your shell:
```{.bash .copy}
export PATH=/usr/lib/llvm-19/bin/:$PATH
```
so you can invoke it as `lldb`. Also export this environment variable:
```{.bash .copy}
export LLDB_DEBUGSERVER_PATH=/usr/lib/llvm-19/bin/lldb-server
```
Pwndbg doesn't use the `lldb` driver binary directly, it drives its own REPL and interacts with LLDB through liblldb.
You can run Pwndbg with LLDB by running:
```{.bash .copy}
uv run pwndbg-lldb [binary-to-debug]
```

## The development environment

After installing Pwndbg like described above, there are a few ways to set up the development environment. The simplest one is by running:
```{.bash .copy}
./setup-dev.sh
```
but you can also use the [docker container](#development-from-docker) or [develop using nix](#development-using-nix).

!!! note
    For a proper development environment you must be able to run Pwndbg with both GDB and LLDB, otherwise you won't be able to use some important development features (like doc generation).

### Development from docker
You can create a Docker image with everything already installed for you. You can use docker compose
```{.bash .copy}
docker compose run -i main
```
or build and run the container with
```{.bash .copy}
docker build -t pwndbg .
docker run -it --cap-add=SYS_PTRACE --security-opt seccomp=unconfined -v `pwd`:/pwndbg pwndbg bash
```

### Development using Nix
Pwndbg supports development with Nix which installs all the required
development dependencies:

1. Install Nix with [Determinate Nix Installer](https://github.com/DeterminateSystems/nix-installer?tab=readme-ov-file#determinate-nix-installer).
2. Enter the development shell with `nix develop` or automate this with `direnv`.
3. Run local changes with `pwndbg` or `pwndbg-lldb`. Run tests with `./tests.sh`.
