from __future__ import annotations

import re

import gdb

import tests

LINKED_LISTS_BINARY = tests.binaries.get("linked-lists.out")


def startup(start_binary) -> None:
    start_binary(LINKED_LISTS_BINARY)

    gdb.execute("break break_here")
    gdb.execute("run")
    gdb.execute("up")


def test_command_plist_dereference_limit_change_has_impact_on_plist(start_binary):
    """
    Tests the plist command with different dereference limits
    """
    startup(start_binary)
    gdb.execute("set dereference-limit 5")
    expected_out = re.compile(
        """\
0[xX][0-9a-fA-F]+ <node_a>: {\\s*
  value = 0,\\s*
  next = 0[xX][0-9a-fA-F]+ <node_b>\\s*
}\\s*
0[xX][0-9a-fA-F]+ <node_b>: {\\s*
  value = 1,\\s*
  next = 0[xX][0-9a-fA-F]+ <node_c>\\s*
}\\s*
0[xX][0-9a-fA-F]+ <node_c>: {\\s*
  value = 2,\\s*
  next = 0[xX][0-9a-fA-F]+ <node_d>\\s*
}\\s*
0[xX][0-9a-fA-F]+ <node_d>: {\\s*
  value = 3,\\s*
  next = 0[xX][0-9a-fA-F]+ <node_e>\\s*
}\\s*
0[xX][0-9a-fA-F]+ <node_e>: {\\s*
  value = 4,\\s*
  next = 0[xX][0-9a-fA-F]+ <node_f>\\s*
}\
"""
    )

    result_str = gdb.execute("plist node_a next", to_string=True)
    assert expected_out.match(result_str) is not None

    gdb.execute("set dereference-limit 1")
    expected_out = re.compile(
        """\
0[xX][0-9a-fA-F]+ <node_a>: {\\s*
  value = 0,\\s*
  next = 0[xX][0-9a-fA-F]+ <node_b>\\s*
}\
"""
    )

    result_str = gdb.execute("plist node_a next", to_string=True)
    assert expected_out.match(result_str) is not None


def test_command_plist_unreached_sentinel_does_not_cause_null_deference(start_binary):
    """
    Tests the plist command with a sentinel set to an address that is not reached does
    not try to dereference zero
    """
    startup(start_binary)
    expected_out = re.compile(
        """\
0[xX][0-9a-fA-F]+ <node_a>: 0\\s*
0[xX][0-9a-fA-F]+ <node_b>: 1\\s*
0[xX][0-9a-fA-F]+ <node_c>: 2\\s*
0[xX][0-9a-fA-F]+ <node_d>: 3\\s*
0[xX][0-9a-fA-F]+ <node_e>: 4\\s*
\
"""
    )

    result_str = gdb.execute("plist node_a next --sentinel 1 -f value", to_string=True)
    assert expected_out.match(result_str) is not None


def test_command_plist_invalid_address_deference_is_displayed_properly(start_binary):
    """
    Tests that the error message is displayed nicely when an incorrect address gets
    deferenced
    """
    startup(start_binary)
    gdb.execute("p node_a->next = 0x1234")
    expected_out = re.compile(
        """\
0[xX][0-9a-fA-F]+ <node_a>: 0\\s*
Cannot dereference 0x1234 for list link #2: Cannot access memory at address 0x1234\\s*
Is the linked list corrupted or is the sentinel value wrong\\?\\s*
\
"""
    )
    result_str = gdb.execute("plist node_a next -f value", to_string=True)
    assert expected_out.match(result_str) is not None


def test_command_plist_flat_with_offset(start_binary):
    """
    Tests the plist for a non-nested linked list with an arbitrary offset value
    """
    startup(start_binary)

    expected_out = re.compile(
        """\
0[xX][0-9a-fA-F]+ <node_d>: {\\s*
  value = 3,\\s*
  next = 0[xX][0-9a-fA-F]+ <node_e>\\s*
}\\s*
0[xX][0-9a-fA-F]+ <node_e>: {\\s*
  value = 4,\\s*
  next = 0[xX][0-9a-fA-F]+ <node_f>\\s*
}\\s*
0[xX][0-9a-fA-F]+ <node_f>: {\\s*
  value = 5,\\s*
  next = 0x0\\s*
}\
"""
    )

    result_str = gdb.execute("plist node_a next -o 3", to_string=True)
    assert expected_out.match(result_str) is not None


def test_command_plist_flat_with_count(start_binary):
    """
    Tests the plist for a non-nested linked list with an arbitrary count value
    """
    startup(start_binary)

    expected_out = re.compile(
        """\
0[xX][0-9a-fA-F]+ <node_a>: {\\s*
  value = 0,\\s*
  next = 0[xX][0-9a-fA-F]+ <node_b>\\s*
}\\s*
0[xX][0-9a-fA-F]+ <node_b>: {\\s*
  value = 1,\\s*
  next = 0[xX][0-9a-fA-F]+ <node_c>\\s*
}\\s*
0[xX][0-9a-fA-F]+ <node_c>: {\\s*
  value = 2,\\s*
  next = 0[xX][0-9a-fA-F]+ <node_d>\\s*
}\
"""
    )

    result_str = gdb.execute("plist node_a next -c 3", to_string=True)
    assert expected_out.match(result_str) is not None


def test_command_plist_flat_no_flags(start_binary):
    """
    Tests the plist for a non-nested linked list
    """
    startup(start_binary)

    expected_out = re.compile(
        """\
0[xX][0-9a-fA-F]+ <node_a>: {\\s*
  value = 0,\\s*
  next = 0[xX][0-9a-fA-F]+ <node_b>\\s*
}\\s*
0[xX][0-9a-fA-F]+ <node_b>: {\\s*
  value = 1,\\s*
  next = 0[xX][0-9a-fA-F]+ <node_c>\\s*
}\\s*
0[xX][0-9a-fA-F]+ <node_c>: {\\s*
  value = 2,\\s*
  next = 0[xX][0-9a-fA-F]+ <node_d>\\s*
}\\s*
0[xX][0-9a-fA-F]+ <node_d>: {\\s*
  value = 3,\\s*
  next = 0[xX][0-9a-fA-F]+ <node_e>\\s*
}\\s*
0[xX][0-9a-fA-F]+ <node_e>: {\\s*
  value = 4,\\s*
  next = 0[xX][0-9a-fA-F]+ <node_f>\\s*
}\
"""
    )

    result_str = gdb.execute("plist node_a next", to_string=True)
    assert expected_out.match(result_str) is not None


def test_command_plist_flat_field(start_binary):
    """
    Tests the plist command for a non-nested linked list with field flag
    """
    startup(start_binary)

    expected_out = re.compile(
        """\
0[xX][0-9a-fA-F]+ <node_a>: 0\\s*
0[xX][0-9a-fA-F]+ <node_b>: 1\\s*
0[xX][0-9a-fA-F]+ <node_c>: 2\\s*
"""
    )

    result_str = gdb.execute("plist node_a next -f value", to_string=True)
    assert expected_out.match(result_str) is not None


def test_command_plist_flat_sentinel(start_binary):
    """
    Tests the plist command for a non-nested linked list with field flag
    """
    startup(start_binary)

    sentinel = int(gdb.lookup_symbol("node_c")[0].value().address)
    expected_out = re.compile(
        """\
0[xX][0-9a-fA-F]+ <node_a>: {\\s*
  value = 0,\\s*
  next = 0[xX][0-9a-fA-F]+ <node_b>\\s*
}\\s*
0[xX][0-9a-fA-F]+ <node_b>: {\\s*
  value = 1,\\s*
  next = 0[xX][0-9a-fA-F]+ <node_c>\\s*
}"""
    )

    result_str = gdb.execute(f"plist node_a next -s {sentinel}", to_string=True)
    assert expected_out.match(result_str) is not None


def test_command_plist_nested_direct(start_binary):
    """
    Tests the plist for a nested linked list pointing to the outer structure
    """
    startup(start_binary)

    expected_out = re.compile(
        """\
0[xX][0-9a-fA-F]+ <inner_b_node_a>: {\\s*
  value = 0,\\s*
  inner = {\\s*
    next = 0[xX][0-9a-fA-F]+ <inner_b_node_b>\\s*
  }\\s*
}\\s*
0[xX][0-9a-fA-F]+ <inner_b_node_b>: {\\s*
  value = 1,\\s*
  inner = {\\s*
    next = 0[xX][0-9a-fA-F]+ <inner_b_node_c>\\s*
  }\\s*
}\\s*
0[xX][0-9a-fA-F]+ <inner_b_node_c>: {\\s*
  value = 2,\\s*
  inner = {\\s*
    next = 0x0\\s*
  }\\s*
}"""
    )

    result_str = gdb.execute("plist inner_b_node_a -i inner next", to_string=True)
    assert expected_out.match(result_str) is not None


def test_command_plist_nested_indirect(start_binary):
    """
    Tests the plist for a nested linked list pointing to the inner structure
    """
    startup(start_binary)

    expected_out = re.compile(
        """\
0[xX][0-9a-fA-F]+ <inner_a_node_a>: {\\s*
  value = 0,\\s*
  inner = {\\s*
    next = 0[xX][0-9a-fA-F]+ <inner_a_node_b\\+8>\\s*
  }\\s*
}\\s*
0[xX][0-9a-fA-F]+ <inner_a_node_b>: {\\s*
  value = 1,\\s*
  inner = {\\s*
    next = 0[xX][0-9a-fA-F]+ <inner_a_node_c\\+8>\\s*
  }\\s*
}\\s*
0[xX][0-9a-fA-F]+ <inner_a_node_c>: {\\s*
  value = 2,\\s*
  inner = {\\s*
    next = 0x0\\s*
  }\\s*
}"""
    )

    result_str = gdb.execute("plist inner_a_node_a -i inner next", to_string=True)
    assert expected_out.match(result_str) is not None
