from __future__ import annotations

import pytest

from pwndbg.lib.common import hex2ptr_common


def test_hex2ptr_common_valid_hex():
    assert hex2ptr_common("00 70 75 c1 cd ef 59 00") == 0x59EFCDC1757000
    assert hex2ptr_common("12 34 56 78") == 0x78563412


def test_hex2ptr_common_invalid_hex():
    # Test for odd-length hex string
    with pytest.raises(ValueError, match="Hex string must contain an even number of characters."):
        hex2ptr_common("12345")

    # Test for invalid hex characters
    with pytest.raises(ValueError, match="Invalid hex string"):
        hex2ptr_common("zz zz zz")


def test_hex2ptr_common_mixed_case():
    """Test that hex2ptr_common correctly handles mixed case hex strings."""
    assert hex2ptr_common("aB cD eF 12") == 0x12EFCDAB
    assert hex2ptr_common("FfFf") == 0xFFFF
