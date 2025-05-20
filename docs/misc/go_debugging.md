# Debugging Go with pwndbg
## Basics
The `go-dump` command can be used to dump Go values during debugging. It takes the form `go-dump type address_expression`, and supports many different types with the same syntax as Go:
- Integer types: `int`, `int8`, `int16`, `int32`, `int64`, `int128`, and their `uint` counterparts
- Misc types: `bool`, `rune`, `uintptr`, `string`
- Floating point types: `float32`, `float64`
- Complex numbers: `complex64`, `complex128`
- Interface types: `any` for `interface{}` (the empty interface), and `interface` for all non-empty interfaces
- Function types: `funcptr` for all function types
- Pointers: `*ELEM`
- Slices: `[]ELEM`
- Arrays: `[LEN]ELEM`
- Maps: `map[KEY][VAL]` (note that maps in Go are actually pointers to the map, whereas this map is the inner map, so you may need to use `*map[KEY]VAL` to dump a map)

Struct types are also supported, but the syntax is slightly different from Go in order to avoid having to compute offsets (and also to support only having partial field information on structs). Struct types are notated as `OFFSET:FIELD_NAME:TYPE` triples separated by semicolons then enclosed with `struct(SIZE){}`, e.g. `struct(24){0:foo:string;16:bar:int64}` to represent the 24-byte Go struct `struct { foo string; bar int64 }`.

Example:
```
pwndbg> go-dump map[string]int 0xc0000b20f0
{"a": 1, "b": 2, "c": 3}

pwndbg> go-dump any 0xc0000ace40
([]struct { a int; b string }) [struct {a: 1, b: "first"}, struct {a: 2, b: "second"}]

pwndbg> go-dump struct(24){0:a:int;8:b:string} 0xc000108120
struct {a: 1, b: "first"}
```

Some notable flags include `-p` to enable pretty printing, `-x` to display integers in hex, `-f DECIMALS` to set the number of decimals used to display floats, `-d` to enable debug printing, which displays memory addresses of everything shown in the dump.

## Runtime Type Parsing
Go's compiler emits type objects for every single type used by the program. This is what enables dumping interface values with `go-dump` without having to specify any additional type information, and can also be leveraged to dump non-interface values if the type can be located. A good way to locate types is by finding the type pointer passed into heap allocation functions like `runtime.newobject` or `runtime.makeslice`.

After finding the type pointer, the `go-type` command can be used to inspect a type:
```
pwndbg> go-type 0x49fbc0
 Name: struct { a int; b string }
 Kind: STRUCT
 Size: 24 (0x18)
Align: 8
Parse: struct(24){0:a:int;8:b:string}
Field a:
    Offset: 0 (0x0)
    Type name: int
    Type addr: 0x498ce0
Field b:
    Offset: 8 (0x8)
    Type name: string
    Type addr: 0x498aa0
```

The `go-dump` command can also take an address to a type instead of the name of a type:
```
pwndbg> go-dump 0x49fbc0 0xc000108120
struct {a: 1, b: "first"}
```
