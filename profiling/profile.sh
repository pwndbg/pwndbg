#!/bin/bash

if ! (($#)); then
    cat <<- _EOF_
		$0: [profile-script]

		Example: $0 context.py
_EOF_
    exit 1
fi

module=$(basename "${1/.py/}")
basedir=$(dirname "$0")

# Quick and dirty script to profile pwndbg using cProfile.
make -C "${basedir}" test > /dev/null

gdb "${basedir}/test" \
    -ex "source ${basedir}/../gdbinit.py" \
    -ex "b main" \
    -ex "r" \
    -ex "python
import cProfile;
import profiling.${module} as profile;
profile.warmup();
cProfile.run('profile.run()', '${basedir}/stats')" \
    -ex "quit"

python3 -c "
import pstats
p = pstats.Stats('${basedir}/stats')
p.strip_dirs().sort_stats('tottime').print_stats(20)
"

if command -v pyprof2calltree &> /dev/null && command -v kcachegrind &> /dev/null; then
    pyprof2calltree -k -i "${basedir}/stats"
fi

# vim: ts=4 sw=4 noet
