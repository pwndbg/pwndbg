from __future__ import annotations

import re

import gdb

from . import start_and_break_on


@start_and_break_on("linked-lists.out", ["break_here"])
def test_command_plist_flat_no_flags():
    """
    Tests the plist for a non-nested linked list
    """
    gdb.execute("up")

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
  next = 0x0\\s*
}"""
    )

    result_str = gdb.execute("plist node_a next", to_string=True)
    assert expected_out.match(result_str) is not None


@start_and_break_on("linked-lists.out", ["break_here"])
def test_command_plist_flat_field():
    """
    Tests the plist command for a non-nested linked list with field flag
    """
    gdb.execute("up")

    expected_out = re.compile(
        """\
0[xX][0-9a-fA-F]+ <node_a>: 0\\s*
0[xX][0-9a-fA-F]+ <node_b>: 1\\s*
0[xX][0-9a-fA-F]+ <node_c>: 2\\s*
"""
    )

    result_str = gdb.execute("plist node_a next -f value", to_string=True)
    assert expected_out.match(result_str) is not None


@start_and_break_on("linked-lists.out", ["break_here"])
def test_command_plist_flat_sentinel():
    """
    Tests the plist command for a non-nested linked list with field flag
    """
    gdb.execute("up")

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


@start_and_break_on("linked-lists.out", ["break_here"])
def test_command_plist_nested_direct():
    """
    Tests the plist for a nested linked list pointing to the outer structure
    """
    gdb.execute("up")

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


@start_and_break_on("linked-lists.out", ["break_here"])
def test_command_plist_nested_indirect():
    """
    Tests the plist for a nested linked list pointing to the inner structure
    """
    gdb.execute("up")

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
