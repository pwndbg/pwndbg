#!/usr/bin/env python
# -*- coding: utf-8 -*-
import glob
import locale
import sys
from os import path, environ

virtual_env = environ.get('VIRTUAL_ENV')


if virtual_env:
    print("Found that you're using VIRTUAL_ENV '%s'" % virtual_env)
    possible_site_packages = glob.glob(path.join(virtual_env, 'lib', 'python*', 'site-packages'))
    if len(possible_site_packages) > 1:
        print("Found multiple site packages in virtualenv, using the last choice.")
    virtualenv_site_packages = []
    for site_packages in possible_site_packages:
        virtualenv_site_packages = site_packages
    if not virtualenv_site_packages:
        print("Not found site-packages in virtualenv, guessing")
        guessed_python_directory = 'python%s.%s' % (sys.version_info.major, sys.version_info.minor)
        virtualenv_site_packages = path.join(virtual_env, 'lib', guessed_python_directory, 'site-packages')
    print("Using virtualenv's python site packages: %s " % virtualenv_site_packages)
    sys.path.append(virtualenv_site_packages)

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
