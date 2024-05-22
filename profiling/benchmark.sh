#!/usr/bin/env bash
# Benchmark context command
make test > /dev/null
git log --abbrev-commit --pretty=oneline HEAD^..HEAD
gdb ./test \
    -ex "source ../gdbinit.py" \
    -ex "b main" -ex "r" \
    -ex "python import timeit; print('      1ST RUN:', timeit.repeat('pwndbg.commands.context.context()', repeat=1, number=1, globals=globals())[0])" \
    -ex "si" \
    -ex "python import timeit; print('      2ND RUN:', timeit.repeat('pwndbg.commands.context.context()', repeat=1, number=1, globals=globals())[0])" \
    -ex "si" \
    -ex "python import timeit; print('MULTIPLE RUNS:', timeit.repeat('pwndbg.commands.context.context()', repeat=1, number=10, globals=globals())[0] / 10)" \
    -ex "quit" | grep 'RUNS*:'
