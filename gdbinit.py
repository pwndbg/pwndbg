#!/usr/bin/env python
# -*- coding: utf-8 -*-
import locale
import sys
from os import path

directory, file = path.split(__file__)
directory       = path.expanduser(directory)
directory       = path.abspath(directory)

sys.path.append(directory)

# warn if the user has different encoding than utf-8
encoding = locale.getpreferredencoding()

if encoding != 'UTF-8':
    print('******')
    print('Your encoding ({}) is different than UTF-8. pwndbg might not work properly.'.format(encoding))
    print('You might try launching gdb with:')
    print('    LC_ALL=en_US.UTF-8 PYTHONIOENCODING=UTF-8 gdb')
    print('Make sure that en_US.UTF-8 is activated in /etc/locale.gen and you called locale-gen')
    print('******')

import pwndbg # isort:skip
