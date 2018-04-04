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

print('Launching pytest with args: %s' % args)

return_code = pytest.main(args)

if return_code != 0:
    print('-' * 80)
    print('If you want to debug tests locally, modify tests_launcher.py and add --pdb to its args')
    print('-' * 80)

sys.exit(return_code)
