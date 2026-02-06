# Packaging Pwndbg

## Stale Arch Linux package

The Arch Linux Pwndbg package is stale as capstone v6 is not yet packaged by arch. See the [gitlab.archlinux.org issue](https://gitlab.archlinux.org/archlinux/packaging/packages/pwndbg/-/issues/4#note_336730), and [our rationale](https://github.com/pwndbg/pwndbg/issues/3555#issuecomment-3701094056).

## Changes for package maintainers

Previously, packagers were required to create a `.skip-venv` file if they wanted to make sure Pwndbg used system installed python packages. Also, they had to deal with the fact that Pwndbg was invoked from the `~/.gdbinit` file.

As of version 2025.10.10, you don't need to worry about those problems anymore. The entrypoints to Pwndbg are the `pwndbg` and `pwndbg-lldb` commands as defined in the `[project.scripts]` section of the `pyproject.toml` file. The `.skip-venv` file is also not necessary as Pwndbg will detect that a virtual environment is not being used at runtime. The method you use to package any python package will just work with Pwndbg without any workarounds.

!!! info
    If you're curious, the PR that introduced these changes is [#3199](https://github.com/pwndbg/pwndbg/pull/3119). There is a general packaging thread in #3124. For reference, the Pwndbg package for Gentoo has been updated in this PR: https://github.com/gentoo/gentoo/pull/44181 (discussed in #3348).

## Using system GDB and LLDB

We package our own builds of [GDB](https://pypi.org/project/gdb-for-pwndbg/) and [LLDB](https://pypi.org/project/lldb-for-pwndbg/) as python packages. When you use our installer script to install Pwndbg, you will be using these builds. This ensures you have the newest versions of the debuggers, which is important for distributions like Ubuntu and Debian which can be quite behind. You also enjoy our patches for those debuggers which guarantee better integration with Pwndbg.

Nevertheless, we will continue to support users using their own system GDB and LLDB indefinitely. As long as they are above the supported version threshold, which is currently >= 12.1 for GDB and >= 19 for LLDB. The reasons for that are:

+ It allows Pwndbg to be packaged by distributions
+ It prevents us from accumulating too many patches on our builds, making it a maintenance burden to rebase
+ It allows other (proprietary) forks of GDB and LLDB to be used with Pwndbg
+ It saves disk space

To facilitate this support, when we encounter an upstream bug, we won't just fix it in our build, but will implement a workaround (depending on how severe the bug is) in Pwndbg itself, and keep it there until the fix is merged upstream and all major distributions have started to ship the backported fix.
