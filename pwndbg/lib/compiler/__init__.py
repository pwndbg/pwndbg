"""
We need a compiler to assemble shellcode and add structures into the debugee.

This module provides an API to a compiler, without exposing which compiler
is being used underneath.

In order we try for: zig, clang, gcc.
"""
