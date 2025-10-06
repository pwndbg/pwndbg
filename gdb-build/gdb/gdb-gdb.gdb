echo Setting up the environment for debugging gdb.\n

if !$gdb_init_done
  set variable $gdb_init_done = 1

  set complaints 1

  b internal_error_loc

  # This provides an easy way to break into the top-level GDB by
  # typing "info".
  b info_command
  commands
    silent
    # This avoids the voluminous output of "info".
    return
  end

  # Commands below are not fully compatible with wrapping into an 'if' block.
end

set prompt (top-gdb) 

define pdie
  if $argc == 1
    call $arg0->dump (1)
  else
    if $argc == 2
      call $arg0->dump ($arg1)
    else
      printf "Syntax: pdie die [depth]\n"
    end
  end
end

document pdie
Pretty print a DWARF DIE.
Syntax: pdie die [depth]
end

# Trivial and uninteresting functions to skip.
skip -rfu "^enum_flags<.*>::enum_flags"
skip -rfu "^gdb::array_view<.*>::array_view"
skip -rfu "^gdb::function_view<.*>::function_view"
skip -rfu "^gdb::ref_ptr<.*>::get"
