# Contributing Guide

## Contributing Overview
Thank you for your interest in contributing to pwndbg!

Note that while it is recommended that your pull request (PR) links to an issue (which can be used for discussing the bug / feature), you do not need to be assigned to it - just create the PR and it will be reviewed.

To start, [install pwndbg from source and set it up for development](setup-pwndbg-dev.md).
For common tasks see:

+ [Adding a command](adding-a-command.md)
+ [Adding a configuration option](adding-a-parameter.md)
+ [Improving annotations](improving-annotations.md)

Regardless of the contents of your PR, you will need to [lint](#linting) and [test](#running-tests) your code so make sure to read those sections. It is also likely you will need to [update the documentation](#updating-documentation).

Read [General developer notes](dev-notes.md) to get more familiar with the various systems in place in pwndbg. If you have any questions don't hesitate to ask us on our [discord server](https://discord.gg/x47DssnGwm)!
## Linting
The `lint.sh` script runs isort, ruff, shfmt, and vermin. isort and ruff (mostly) are able to automatically fix any issues they detect. You may apply all available fixes by running
```{.bash .copy}
./lint.sh -f
```
!!! note
    You can find the configuration files for these tools in `pyproject.toml` or by checking the arguments passed inside `lint.sh`.

When submitting a PR, the continuous integration (CI) job defined in `.github/workflows/lint.yml` will verify that running `./lint.sh` succeeds, otherwise the job will fail and we won't be able to merge your PR.

It is recommended to enable the pre-push git hook to run the lint if you haven't already done so. You may re-run `./setup-dev.sh` to set it.
## Running tests
Your PR will not be merged without passing the testing CI. Moreover, it is highly recommended you write a new test or update an existing test whenever adding new functionality to pwndbg. To see how to do this, check out [Writing tests](writing-tests.md).

To run the tests in the same environment as the testing CI, you can use the following docker commands.
```{.bash .copy}
# General (x86_64) test suite
docker compose run --rm --build ubuntu24.04-mount ./tests.sh
# Cross-architecture tests
docker compose run --rm --build ubuntu24.04-mount ./qemu-tests.sh
# Unit tests
docker compose run --rm --build ubuntu24.04-mount ./unit-tests.sh
```
This comes in handy particularly for cross-architecture tests because the docker environment has all the cross-compilers installed. The active `pwndbg` directory is mounted, preventing the need for a full rebuild whenever you update the codebase.

Remove the `-mount` if you want the tests to run from a clean slate (no files are mounted, meaning all binaries are recompiled each time).

If you wish to focus on some failing tests, you can filter the tests to run by providing an argument to the script, such as `<docker..> ./tests.sh heap`, which will only run tests that contain "heap" in the name. See `./tests.sh --help` for more information and other options. You can also do this with the cross-arch tests.

If you want to, you may also [run the tests with nix](#running-tests-with-nix) or [run them bare](#running-without-docker).

TODO: Create a script for running kernel tests instead of running them with `./tests/qemu-tests/tests.sh`.

#### Running tests with nix
You will need to build a nix-compatible `gdbinit.py` file, which you can do with
```{.bash .copy}
nix build .#pwndbg-dev
```
Then simply run the test by adding the `--nix` flag:
```{.bash .copy}
./tests.sh --nix [filter]
```
#### Running without docker
If you wish to improve pwndbg support for your distribution (or the testing infrastructure) you may run the testing suite without the docker container.

The commands are analogous to the docker commands.
```{.bash .copy}
# General (x86_64) test suite
./tests.sh
# Cross-architecture tests
./qemu-tests.sh
# Unit tests
./unit-tests.sh
```

To run the kernel tests you will need to install the appropriate qemu-system packages for your distribution. Then download the kernel images with
```{.bash .copy}
./tests/qemu-tests/download_images.sh
```
set ptrace_scope to zero with
```{.bash .copy}
echo 0 | sudo tee /proc/sys/kernel/yama/ptrace_scope
```
and run the kernel tests with
```{.bash .copy}
cd ./tests/qemu-tests/ && ./tests.sh
```

## Updating Documentation
TODO
