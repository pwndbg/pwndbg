from __future__ import print_function
from __future__ import division
from __future__ import absolute_import
from __future__ import unicode_literals

import os
import pytest
import sys
print(sys.argv)

sys._pwndbg_unittest_run = True

TESTS_PATH = os.path.join(
    os.path.dirname(os.path.realpath(__file__)),
    'tests'
)

# If you want to debug tests locally, add '--pdb' here
args = [TESTS_PATH, '-vvv', '-s', '--showlocals', '--color=yes']

additional_args = os.environ.get('PWNDBG_PYTEST_ADD_OPTS', '').split(' ')

if additional_args != ['']:
    args += additional_args

print('Launching pytest with args: %s' % args)

return_code = pytest.main(args)

dashes = '-' * 95
print(dashes)
print("Tests are written with pytest and are launched through GDB's Python interpreter")
print('To pass some arguments to pytest (see `pytest -h`) either modify pytest_launcher.py')
print('or set an environment variable `PWNDBG_PYTEST_ADD_OPTS` which will be added to pytest args')
print(dashes)

sys.exit(return_code)
