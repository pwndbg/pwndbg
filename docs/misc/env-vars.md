## Environment Variables

Pwndbg relies on several environment variables to customize its behavior. Below is a list of these variables and their purposes:

- `PATH`: Standard system `PATH` variable used to locate executables.
- `EDITOR`, `VISUAL`: Used by the `cymbol` command to open an editor.
- `HOME`, `XDG_CACHE_HOME`: Used by `lib.tempfile` to determine temporary file locations.
- `PWNDBG_VENV_PATH`: Specifies the virtual environment path for Pwndbg.
- `PWNDBG_DISABLE_COLORS`: Disables colored output in Pwndbg.
- `PWNDBG_LOGLEVEL`: Initial log level to use for log messages.
- `OPENAI_API_KEY`, `ANTHROPIC_API_KEY`: Used by the `ai` command for accessing respective AI APIs.
- `GITHUB_ACTIONS`, `RUN_FLAKY`: Used by `tests_commands.py` to determine the test environment.
- `PWNDBG_PROFILE`: Enables profiling for benchmarking.
- `USE_PDB`: Enables Python debugger in tests.
- `PWNDBG_LAUNCH_TEST`: Used by tests to configure test launching.
- `PWNDBG_ARCH`, `PWNDBG_KERNEL_TYPE`, `PWNDBG_KERNEL_VERSION`: Used by `gdblib` kernel tests to specify kernel parameters.
- `SPHINX`: Used by `docs/source/conf.py`, likely to be removed.
- `PWNLIB_NOTERM=1`: Set by Pwndbg to avoid terminal issues with Pwntools.
