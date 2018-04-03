from __future__ import print_function
from __future__ import division
from __future__ import absolute_import
from __future__ import unicode_literals

import pytest
import sys

sys._pwndbg_unittest_run = True

# If you want to debug tests locally, add '--pdb' here
args = ['./tests/', '--pdb', '-vvv', '-s', '--showlocals', '--color=yes']

print('Launching pytest with args: %s' % args)

return_code = pytest.main(args)

sys.exit(return_code)
