from __future__ import annotations

import re

from . import break_at_sym
from . import get_binary
from . import get_expr
from . import pwndbg_test

LINKED_LISTS_BINARY = get_binary("linked-lists.out")


async def startup(ctrl: Controller):
    await ctrl.launch(LINKED_LISTS_BINARY)

    break_at_sym("break_here")
    await ctrl.cont()
    await ctrl.execute("up")


@pwndbg_test
async def test_command_plist_dereference_limit_change_has_impact_on_plist(ctrl: Controller):
    """
    Tests the plist command with different dereference limits
    """
    await startup(ctrl)
    await ctrl.execute("set dereference-limit 5")
    expected_out = re.compile(
        """\
0[xX][0-9a-fA-F]+ <node_a>:.*{\\s*
  value = 0,?\\s*
  next = 0[xX][0-9a-fA-F]+( <node_b>)?,?\\s*
}\\s*
0[xX][0-9a-fA-F]+ <node_b>:.*{\\s*
  value = 1,?\\s*
  next = 0[xX][0-9a-fA-F]+( <node_c>)?,?\\s*
}\\s*
0[xX][0-9a-fA-F]+ <node_c>:.*{\\s*
  value = 2,?\\s*
  next = 0[xX][0-9a-fA-F]+( <node_d>)?,?\\s*
}\\s*
0[xX][0-9a-fA-F]+ <node_d>:.*{\\s*
  value = 3,?\\s*
  next = 0[xX][0-9a-fA-F]+( <node_e>)?,?\\s*
}\\s*
0[xX][0-9a-fA-F]+ <node_e>:.*{\\s*
  value = 4,?\\s*
  next = 0[xX][0-9a-fA-F]+( <node_f>)?,?\\s*
}\
"""
    )

    result_str = await ctrl.execute_and_capture("plist node_a next")
    print(result_str)
    assert expected_out.match(result_str) is not None

    await ctrl.execute("set dereference-limit 1")
    expected_out = re.compile(
        """\
0[xX][0-9a-fA-F]+ <node_a>:.*{\\s*
  value = 0,?\\s*
  next = 0[xX][0-9a-fA-F]+( <node_b>)?,?\\s*
}\
"""
    )

    result_str = await ctrl.execute_and_capture("plist node_a next")
    assert expected_out.match(result_str) is not None


@pwndbg_test
async def test_command_plist_unreached_sentinel_does_not_cause_null_deference(ctrl: Controller):
    """
    Tests the plist command with a sentinel set to an address that is not reached does
    not try to dereference zero
    """
    await startup(ctrl)
    expected_out = re.compile(
        """\
0[xX][0-9a-fA-F]+ <node_a>:.* 0\\s*
0[xX][0-9a-fA-F]+ <node_b>:.* 1\\s*
0[xX][0-9a-fA-F]+ <node_c>:.* 2\\s*
0[xX][0-9a-fA-F]+ <node_d>:.* 3\\s*
0[xX][0-9a-fA-F]+ <node_e>:.* 4\\s*
\
"""
    )

    result_str = await ctrl.execute_and_capture("plist node_a next --sentinel 1 -f value")
    assert expected_out.match(result_str) is not None


@pwndbg_test
async def test_command_plist_invalid_address_deference_is_displayed_properly(ctrl: Controller):
    """
    Tests that the error message is displayed nicely when an incorrect address gets
    deferenced
    """
    await startup(ctrl)
    await ctrl.execute("p node_a->next = (node*) 0x1234")
    expected_out = re.compile(
        """\
0[xX][0-9a-fA-F]+ <node_a>:.* 0\\s*
Cannot dereference 0x1234 for list link #2:.*\\s*
Is the linked list corrupted or is the sentinel value wrong\\?\\s*
\
"""
    )
    result_str = await ctrl.execute_and_capture("plist node_a next -f value")
    assert expected_out.match(result_str) is not None


@pwndbg_test
async def test_command_plist_flat_with_offset(ctrl: Controller):
    """
    Tests the plist for a non-nested linked list with an arbitrary offset value
    """
    await startup(ctrl)

    expected_out = re.compile(
        """\
0[xX][0-9a-fA-F]+ <node_d>:.*{\\s*
  value = 3,?\\s*
  next = 0[xX][0-9a-fA-F]+( <node_e>)?,?\\s*
}\\s*
0[xX][0-9a-fA-F]+ <node_e>:.*{\\s*
  value = 4,?\\s*
  next = 0[xX][0-9a-fA-F]+( <node_f>)?,?\\s*
}\\s*
0[xX][0-9a-fA-F]+ <node_f>:.*{\\s*
  value = 5,?\\s*
  next = (0x0|NULL),?\\s*
}\
"""
    )

    result_str = await ctrl.execute_and_capture("plist node_a next -o 3")
    assert expected_out.match(result_str) is not None


@pwndbg_test
async def test_command_plist_flat_with_count(ctrl: Controller):
    """
    Tests the plist for a non-nested linked list with an arbitrary count value
    """
    await startup(ctrl)

    expected_out = re.compile(
        """\
0[xX][0-9a-fA-F]+ <node_a>:.*{\\s*
  value = 0,?\\s*
  next = 0[xX][0-9a-fA-F]+( <node_b>)?,?\\s*
}\\s*
0[xX][0-9a-fA-F]+ <node_b>:.*{\\s*
  value = 1,?\\s*
  next = 0[xX][0-9a-fA-F]+( <node_c>)?,?\\s*
}\\s*
0[xX][0-9a-fA-F]+ <node_c>:.*{\\s*
  value = 2,?\\s*
  next = 0[xX][0-9a-fA-F]+( <node_d>)?,?\\s*
}\
"""
    )

    result_str = await ctrl.execute_and_capture("plist node_a next -c 3")
    assert expected_out.match(result_str) is not None


@pwndbg_test
async def test_command_plist_flat_no_flags(ctrl: Controller):
    """
    Tests the plist for a non-nested linked list
    """
    await startup(ctrl)

    expected_out = re.compile(
        """\
0[xX][0-9a-fA-F]+ <node_a>:.*{\\s*
  value = 0,?\\s*
  next = 0[xX][0-9a-fA-F]+( <node_b>)?,?\\s*
}\\s*
0[xX][0-9a-fA-F]+ <node_b>:.*{\\s*
  value = 1,?\\s*
  next = 0[xX][0-9a-fA-F]+( <node_c>)?,?\\s*
}\\s*
0[xX][0-9a-fA-F]+ <node_c>:.*{\\s*
  value = 2,?\\s*
  next = 0[xX][0-9a-fA-F]+( <node_d>)?,?\\s*
}\\s*
0[xX][0-9a-fA-F]+ <node_d>:.*{\\s*
  value = 3,?\\s*
  next = 0[xX][0-9a-fA-F]+( <node_e>)?,?\\s*
}\\s*
0[xX][0-9a-fA-F]+ <node_e>:.*{\\s*
  value = 4,?\\s*
  next = 0[xX][0-9a-fA-F]+( <node_f>)?,?\\s*
}\
"""
    )

    result_str = await ctrl.execute_and_capture("plist node_a next")
    assert expected_out.match(result_str) is not None


@pwndbg_test
async def test_command_plist_flat_field(ctrl: Controller):
    """
    Tests the plist command for a non-nested linked list with field flag
    """
    await startup(ctrl)

    expected_out = re.compile(
        """\
0[xX][0-9a-fA-F]+ <node_a>:.* 0\\s*
0[xX][0-9a-fA-F]+ <node_b>:.* 1\\s*
0[xX][0-9a-fA-F]+ <node_c>:.* 2\\s*
"""
    )

    result_str = await ctrl.execute_and_capture("plist node_a next -f value")
    assert expected_out.match(result_str) is not None


@pwndbg_test
async def test_command_plist_flat_sentinel(ctrl: Controller):
    """
    Tests the plist command for a non-nested linked list with field flag
    """
    await startup(ctrl)

    sentinel = int(get_expr("node_c").address)
    expected_out = re.compile(
        """\
0[xX][0-9a-fA-F]+ <node_a>:.*{\\s*
  value = 0,?\\s*
  next = 0[xX][0-9a-fA-F]+( <node_b>)?,?\\s*
}\\s*
0[xX][0-9a-fA-F]+ <node_b>:.*{\\s*
  value = 1,?\\s*
  next = 0[xX][0-9a-fA-F]+( <node_c>)?,?\\s*
}"""
    )

    result_str = await ctrl.execute_and_capture(f"plist node_a next -s {sentinel}")
    assert expected_out.match(result_str) is not None


@pwndbg_test
async def test_command_plist_nested_direct(ctrl: Controller):
    """
    Tests the plist for a nested linked list pointing to the outer structure
    """
    await startup(ctrl)

    expected_out = re.compile(
        """\
0[xX][0-9a-fA-F]+ <inner_b_node_a>:.*{\\s*
  value = 0,?\\s*
  inner = {\\s*
    next = 0[xX][0-9a-fA-F]+( <inner_b_node_b>)?,?\\s*
  }\\s*
}\\s*
0[xX][0-9a-fA-F]+ <inner_b_node_b>:.*{\\s*
  value = 1,?\\s*
  inner = {\\s*
    next = 0[xX][0-9a-fA-F]+( <inner_b_node_c>)?,?\\s*
  }\\s*
}\\s*
0[xX][0-9a-fA-F]+ <inner_b_node_c>:.*{\\s*
  value = 2,?\\s*
  inner = {\\s*
    next = (0x0|NULL),?\\s*
  }\\s*
}"""
    )

    result_str = await ctrl.execute_and_capture("plist inner_b_node_a -i inner next")
    assert expected_out.match(result_str) is not None


@pwndbg_test
async def test_command_plist_nested_indirect(ctrl: Controller):
    """
    Tests the plist for a nested linked list pointing to the inner structure
    """
    await startup(ctrl)

    expected_out = re.compile(
        """\
0[xX][0-9a-fA-F]+ <inner_a_node_a>:.*{\\s*
  value = 0,?\\s*
  inner = {\\s*
    next = 0[xX][0-9a-fA-F]+( <inner_a_node_b\\+8>)?,?\\s*
  }\\s*
}\\s*
0[xX][0-9a-fA-F]+ <inner_a_node_b>:.*{\\s*
  value = 1,?\\s*
  inner = {\\s*
    next = 0[xX][0-9a-fA-F]+( <inner_a_node_c\\+8>)?,?\\s*
  }\\s*
}\\s*
0[xX][0-9a-fA-F]+ <inner_a_node_c>:.*{\\s*
  value = 2,?\\s*
  inner = {\\s*
    next = (0x0|NULL),?\\s*
  }\\s*
}"""
    )

    result_str = await ctrl.execute_and_capture("plist inner_a_node_a -i inner next")
    assert expected_out.match(result_str) is not None
