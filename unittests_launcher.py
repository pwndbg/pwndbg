from __future__ import print_function
from __future__ import division
from __future__ import absolute_import
from __future__ import unicode_literals

import pytest
import sys

sys._pwndbg_unittest_run = True

return_code = pytest.main(['./pwndbg/tests', '-vvv', '-s'])

sys.exit(return_code)
