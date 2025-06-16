# Contributing Guide

## Contributing Overview
Thank you for your interest in contributing to Pwndbg!

Note that while it is recommended that your pull request (PR) links to an issue (which can be used for discussing the bug / feature), you do not need to be assigned to it - just create the PR and it will be reviewed.

To start, [install Pwndbg from source and set it up for development](setup-pwndbg-dev.md).
For common tasks see:

+ [Adding a command](adding-a-command.md)
+ [Adding a configuration option](adding-a-parameter.md)
+ [Improving annotations](improving-annotations.md)

Regardless of the contents of your PR, you will need to [lint](#linting) and [test](#running-tests) your code so make sure to read those sections. It is also likely you will need to [update the documentation](#updating-documentation).

Read [General developer notes](dev-notes.md) to get more familiar with the various systems in place in Pwndbg. If you have any questions don't hesitate to ask us on our [discord server](https://discord.gg/x47DssnGwm)!
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
Your PR will not be merged without passing the testing CI. Moreover, it is highly recommended you write a new test or update an existing test whenever adding new functionality to Pwndbg. To see how to do this, check out [Writing tests](writing-tests.md).

To run the tests in the same environment as the testing CI, you can use the following docker commands.
```{.bash .copy}
# General (x86_64) test suite
docker compose run --rm --build ubuntu24.04-mount ./tests.sh -d gdb -g gdb
# Cross-architecture tests
docker compose run --rm --build ubuntu24.04-mount ./tests.sh -d gdb -g cross-arch-user
# Kernel tests (x86_64 and aarch64)
docker compose run --rm --build ubuntu24.04-mount ./kernel-tests.sh
# Unit tests
docker compose run --rm --build ubuntu24.04-mount ./unit-tests.sh
```
This comes in handy particularly for cross-architecture tests because the docker environment has all the cross-compilers installed. The active `pwndbg` directory is mounted, preventing the need for a full rebuild whenever you update the codebase.

Remove the `-mount` if you want the tests to run from a clean slate (no files are mounted, meaning all binaries are recompiled each time).

If you wish to focus on some failing tests, you can filter the tests to run by providing an argument to the script, such as `<docker..> ./tests.sh heap`, which will only run tests that contain "heap" in the name. See `./tests.sh --help` for more information and other options. You can also do this with the cross-arch and kernel tests.

If you want to, you may also [run the tests with nix](#running-tests-with-nix) or [run them bare](#running-without-docker).

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
If you wish to improve Pwndbg support for your distribution (or the testing infrastructure) you may run the testing suite without the docker container.

The commands are analogous to the docker commands.
```{.bash .copy}
# General (x86_64) test suite
./tests.sh -d gdb -g gdb
# Cross-architecture tests
./tests.sh -d gdb -g cross-arch-user
# Kernel tests (x86_64 and aarch64)
./kernel-tests.sh
# Unit tests
./unit-tests.sh
```

## Updating Documentation
All the documentation is written in markdown files in the `./docs/` folder. The docs are built into a website using [mkdocs](https://www.mkdocs.org/) (you may see the configuration in `./mkdocs.yml`), pushed to the gh-pages branch, and published via [github pages](https://pages.github.com/). All of this happens in the CI.

In general, for your PR to be accepted you will only need to [Update the auto-generated documentation](#update-the-auto-generated-documentation).

### Update the auto-generated documentation
The `./docs/commands`, `./docs/functions`, and `./docs/configuration` folders are automatically generated[^1] by extracting the necessary information from the source code. If your changes modify things like a command's description, a configuration's valid values, a [convenience function's](../functions/index.md) arguments - i.e. pretty much anything that's user-facing - you must run
```{.bash .copy}
./scripts/generate-docs.sh
```
to update the documentation. You need to have a supported version of GDB *and* [LLDB installed](setup-pwndbg-dev.md#running-with-lldb) for this to work. Commit these changes in a separate commit.

If you forget to do that the CI will detect a discrepency between the documentation and source code (using the `./scripts/verify-docs.sh` script, which you may also invoke yourself) and prevent your PR from being merged (until you push new changes, re-running the CI).

### Manual updates
Of course, if you wish to update some other part of the documentation, you may simply modify the necessary markdown files. All autogenerated files (or parts of files) will have noticable markers written as markdown comments, for instance:
```md
<!-- THIS PART OF THIS FILE IS AUTOGENERATED. DO NOT MODIFY IT. See scripts/generate-docs.sh -->
```
In case you want to add something that cannot be cleanly viewed from the debugger, like a video, screenshot, or long example, every command markdown file also has a dedicated part at the bottom for hand-written text which you can use. The `./scripts/generate-docs.sh` script will never delete these hand-written parts, so if you are for instance renaming a command you will have to transfer this part by copy pasting it to the new file.

If you wish to preview the documentation locally, you may do so by running:
```{.bash .copy}
./scripts/docs-live.sh
```
The build will take some time due to the `Source` section being built. You may disable this by temporarily commenting these lines
```
  - api-autonav:
      modules: ['pwndbg']
      nav_section_title: "Source"
```
in the `mkdocs.yml` file. This will provide much faster build times (but make sure not to commit those changes!). Visit `http://127.0.0.1:8000/pwndbg/` to see the docs. Note that the `Home` section will not be available (it is generated in the CI by copying the README.md), and the site will lack the version selector.

[^1]: Actually, the `./docs/configuration/index.md` file is hand-written, and the intro text to the `./docs/functions/index.md` file is defined in the doc generating file's source code.
