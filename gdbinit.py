#!/usr/bin/env python
# -*- coding: utf-8 -*-
from __future__ import print_function
from __future__ import unicode_literals

import locale
import sys
from os import path

import six

directory, file = path.split(__file__)
directory       = path.expanduser(directory)
directory       = path.abspath(directory)

sys.path.append(directory)

# this is an unconventional workaround to
# support unicode printing for python2
# https://github.com/pwndbg/pwndbg/issues/117
# on python3 it warns if the user has different
# encoding than utf-8
encoding = locale.getpreferredencoding()
if six.PY2:
    reload(sys)
    sys.setdefaultencoding('utf-8')

elif encoding != 'UTF-8':
    print('******')
    print('Your encoding ({}) is different than UTF-8. pwndbg might not work properly.'.format(encoding))
    print('You might try launching gdb with:')
    print('    LC_ALL=en_US.UTF-8 PYTHONIOENCODING=UTF-8 gdb')
    print('Make sure that en_US.UTF-8 is activated in /etc/locale.gen and you called locale-gen')
    print('******')

import pwndbg # isort:skip
