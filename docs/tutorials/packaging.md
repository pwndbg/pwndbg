# Packaging Pwndbg

Previously, packagers were required to create a `.skip-venv` file if they wanted to make sure Pwndbg used system installed python packages. Also, they had to deal with the fact that Pwndbg was invoked from the `~/.gdbinit` file.

As of version 2025.10.10, you don't need to worry about those problems anymore. The entrypoints to Pwndbg are the `pwndbg` and `pwndbg-lldb` commands as defined in the `[project.scripts]` section of the `pyproject.toml` file. The `.skip-venv` file is also not necessary as Pwndbg will detect that a virtual environment is not being used at runtime. The method you use to package any python package will just work with Pwndbg without any workarounds.

!!! info
    If you're curious, the PR that introduced these changes is [#3199](https://github.com/pwndbg/pwndbg/pull/3119). There is a general packaging thread in #3124. For reference, the Pwndbg package for Gentoo has been updated in this PR: https://github.com/gentoo/gentoo/pull/44181.
