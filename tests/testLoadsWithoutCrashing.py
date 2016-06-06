import common

def test_loads_witout_crashing():
    output = common.run_gdb_with_script()
    assert 'Type pwndbg for a list' in output, output