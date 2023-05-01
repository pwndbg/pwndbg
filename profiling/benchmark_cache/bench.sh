#!/bin/sh
# Benchmarks current and old version of pwndbg (provided as git commit)
# Usage: bench.sh <old-commit>
rm *.prof *.stats

set -e

# Current code, benchmark 1
gdb --batch --ex 'entry' --ex 'source gdbscript1.py' --args $(which python3) -c 'import sys; sys.exit(0)'
mv profile.prof curr1.prof
python3 ../print_stats.py curr1.prof > curr1.stats

# Current code, benchmark 2
gdb --batch --ex 'entry' --ex 'source gdbscript2.py' --args $(which python3) -c 'import sys; sys.exit(0)'
mv profile.prof curr2.prof
python3 ../print_stats.py curr2.prof > curr2.stats

# Switch to old version
git checkout $1

# Old code, benchmark 1
gdb --batch --ex 'entry' --ex 'source gdbscript1.py' --args $(which python3) -c 'import sys; sys.exit(0)'
mv profile.prof old1.prof
python3 ../print_stats.py old1.prof > old1.stats

# Old code, benchmark 2
gdb --batch --ex 'entry' --ex 'source gdbscript2.py' --args $(which python3) -c 'import sys; sys.exit(0)'
mv profile.prof old2.prof
python3 ../print_stats.py old2.prof > old2.stats

git checkout -
