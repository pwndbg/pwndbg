from __future__ import annotations

import io
import sys

from pwndbg.color import theme
from pwndbg.color.theme import VALID_COLORS


def _cap_stderr(func, *args, **kwargs):
    """Helper to capture stderr output from color parameter setting."""
    buf = io.StringIO()
    old_stderr = sys.stderr
    sys.stderr = buf
    try:
        func(*args, **kwargs)
    finally:
        sys.stderr = old_stderr
    return buf.getvalue()


def _set_param_value(param, value):
    """Mimic pwndbg config set behavior."""
    return _cap_stderr(param.set, value)


def test_invalid_value_rejects_and_reverts_like_enum():
    p = theme.add_color_param("t-invalid-revert", "yellow", "desc")
    assert p.value == "yellow"
    err = _set_param_value(p, "blabstarst")
    assert "error: invalid color 'blabstarst'" in err
    assert p.value == "yellow"  # reverted to last good


def test_partial_invalid_keeps_valid_subset_and_warns():
    p = theme.add_color_param("t-partial", "yellow", "desc")
    err = _set_param_value(p, "red,meow")
    assert "Invalid color 'meow' ignored" in err
    assert p.value == "red"  # valid part kept


def test_valid_values_set_cleanly_no_warnings():
    p = theme.add_color_param("t-valid", "yellow", "desc")
    err = _set_param_value(p, "green,bold")
    assert err == ""  # no warnings
    assert p.value == "green,bold"


def test_multiple_invalid_attempts_keep_previous_value():
    p = theme.add_color_param("t-multi", "yellow", "desc")
    _set_param_value(p, "purple")
    assert p.value == "purple"
    _set_param_value(p, "shiba")
    assert p.value == "purple"  # previous good retained


def test_show_value_after_invalid_input_is_reverted():
    p = theme.add_color_param("t-show", "yellow", "desc")
    _set_param_value(p, "cyan")
    _set_param_value(p, "invalid_color")
    assert p.value == "cyan"  # reverted to last good


def test_color_function_stays_callable_after_invalid():
    p = theme.add_color_param("t-crash", "yellow", "desc")
    _set_param_value(p, "blue")
    out = p.color_function("hi")
    assert "hi" in out


def test_supported_color_names_are_enum_like():
    # Spot checks only (avoid over-coupling to the exact set)
    assert "yellow" in VALID_COLORS
    assert "bold" in VALID_COLORS
    assert "underline" in VALID_COLORS
    assert "shiba" not in VALID_COLORS


def test_none_maps_to_normal_safely():
    p = theme.add_color_param("t-none", "yellow", "desc")
    _set_param_value(p, "none")
    assert p.value == "normal"

