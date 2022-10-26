#!/usr/bin/env bash
set -ex
cat > $1.rst << EOF
:mod:\`pwndbg.$1\` --- pwndbg.$1
=============================================

.. automodule:: pwndbg.$1
    :members:
EOF
