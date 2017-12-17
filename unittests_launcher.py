import pytest
import sys

sys._pwndbg_unittest_run = True

return_code = pytest.main(['./pwndbg/tests', '-vvv', '-s'])

sys.exit(return_code)
