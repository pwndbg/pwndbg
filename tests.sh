#!/usr/bin/env bash

# Run integration tests
(cd tests/gdb-tests && python3 tests.py $@)
exit_code=$?

COV=0
NIX=0
# Run unit tests
for arg in "$@"; do
    if [ "$arg" == "--cov" ]; then
        COV=1
    elif [ "$arg" == "--nix" ]; then
        NIX=1
    fi
done

if [ $COV -eq 1 ]; then
    coverage run -m pytest tests/unit-tests
else
    if [ $NIX -eq 1 ]; then
        if [ ! -e result/share/pwndbg/ ]; then
            echo "ERROR: Missing expected nix pwndbg folder. Run: nix build .#pwndbg-dev"
            exit 1
        fi
        TMPDIR=$(mktemp -d)
        echo "" > "${TMPDIR}/pytest.ini"
        pytest -c"${TMPDIR}/pytest.ini" -o "pythonpath=$PWD/result/share/pwndbg/" tests/unit-tests
    else
        pytest tests/unit-tests
    fi
fi

exit_code=$((exit_code + $?))

exit $exit_code
