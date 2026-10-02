# Debugging C++

See [Symbol mangling](./mangling.md) and [Pretty printing](./pretty-printing.md) for tutorials on how to cope.

The unfortunate reality is that due to C++'s extensive use of templating, you will have stuff like this:
```c
#include <string>
#include <vector>

int main () {
  std::vector<std::string> string_vec;
  string_vec.push_back("hey");

  puts(string_vec.front().c_str());

  return 0;
}
```
Turn to
```
 ► 0x55555555623d <main+84>     mov    rdi, rax                RDI => 0x7fffffffded0 ◂— 0
   0x555555556240 <main+87>     call   std::vector<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > > >::push_back(std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >&&)
 
   0x555555556245 <main+92>     lea    rax, [rbp - 0x40]
   0x555555556249 <main+96>     mov    rdi, rax
```
(if you're lucky). To my knowledge, not much you can do about that [^1].

If the length of the output is really bothering you, you can set `set print asm-demangle off` to reduce it
significantly at least in the `x/i` GDB output. However, seeing the full demangled name does actually help
quite a bit with figuring out what the function does, so I would recommend keeping demangling on.

## Casting types

If you have pretty printers for libstdc++ enabled, you will see stuff like this:
```
pwndbg> ptype string_vec
type = std::vector<std::string>
```
but if you actually try to use that type:
```
pwndbg> p *(std::vector<std::string> *) (0x7fffffffded0)
❌ A syntax error in expression, near `) (0x7fffffffded0)'.
pwndbg> p (std::vector<std::string>) (0x7fffffffded0)
❌ No symbol "vector<std::string>" in namespace "std".
```
GDB is not gonna let you.

What you *can* do though, is print the raw type, and then use that:
```
pwndbg> ptype/r string_vec
type = class std::vector<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > > > 
        : protected std::_Vector_base<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > > > {

    static bool _S_nothrow_relocate(std::true_type);
    static bool _S_nothrow_relocate(std::false_type);
    static bool _S_use_relocate(void);
[ommitted for brevity]
}

pwndbg> p *(std::vector<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> >, std::allocator<std::__cxx11::basic_string<char, std::char_traits<char>, std::allocator<char> > > > *) 0x7fffffffded0
$4 = std::vector of length 1, capacity 1 = {"hey"}
pwndbg>
```
Note that the format is `p *(type *) address`, and that we did not include the `class` keyword from the `ptype/r` output.

[^1]: Maybe we could implement some simple string substitution in Pwndbg just for the few common cases?
