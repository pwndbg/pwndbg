# Pretty printing

Feel free to add more info if you know more about the topic!

For more about C++ specifically, see [Debugging C++](./debugging-cxx.md).

## Enabling C++ pretty printers

Say you have something like
```cpp
#include <string>
#include <vector>

int main () {
  std::vector<std::string> string_vec;
  string_vec.push_back("hey");

  puts(string_vec.front().c_str());

  return 0;
}
```
In GDB when you do `p string_vec` you will see:
```
pwndbg> p string_vec
$3 = {
  <std::_Vector_base<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > > >> = {
    _M_impl = {
      <std::allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > >> = {
        <std::__new_allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > >> = {<No data fields>},
        <No data fields>
      },
      <std::_Vector_base<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > > >::_Vector_impl_data> = {
        _M_start = 0x0,
        _M_finish = 0x0,
        _M_end_of_storage = 0x0
      },
      <No data fields>
    }
  },
  <No data fields>
}
```
Sometimes you want this, but generally not (especially if you have multiple nested structures).

GCC on most distributions (citation needed) ships with pretty printers to help with this, you can put this
in your `~/.gdbinit`:
```{.python .copy}
# pretty printers
# TODO: find more stable solution since gcc version is hardcoded
python
import sys
sys.path.insert(0, '/usr/share/gcc-16/python')
from libstdcxx.v6.printers import register_libstdcxx_printers
register_libstdcxx_printers (None)
end
```
Check what version of GCC you actually have in `/usr/share/`.

After this, you can print vectors nicely:
```
pwndbg> p string_vec
$2 = std::vector of length 1, capacity 1 = {"hey"}
```
Yay!

If you ever need the raw version, you can use `p/r string_vec`!
