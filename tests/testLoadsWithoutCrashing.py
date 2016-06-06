import common

def test_loads_wivout_crashing_bruv():
    output = common.run_gdb_with_script()
    assert 'Type pwndbg for a list' in output, output