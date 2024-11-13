from __future__ import annotations

from pwndbg.lib.common import hex2ptr_common


def test_hex2ptr_common_valid_hex():
    assert hex2ptr_common("00 70 75 c1 cd ef 59 00") == 0x59EFCDC1757000
    assert hex2ptr_common("12 34 56 78") == 0x78563412


def test_hex2ptr_common_invalid_hex():
    try:
        hex2ptr_common("12345")
    except ValueError:
        pass
    else:
        assert False, "Expected ValueError for odd-length hex string"

    try:
        hex2ptr_common("zz zz zz")
    except ValueError:
        pass
    else:
        assert False, "Expected ValueError for invalid hex characters"
