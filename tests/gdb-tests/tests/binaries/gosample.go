package main

import "fmt"

func testFunc(x interface{}) *interface{} {
	fmt.Println(x)
	return &x // leak x to force it to be allocated somewhere
}

func main() {
	testFunc(map[string]int{"a": 1, "b": 2, "c": 3})
	testFunc([]struct {
		a int
		b string
	}{{a: 1, b: "first"}, {a: 2, b: "second"}})
	testFunc([3]complex64{1.1 + 2.2i, -2.5 - 5i, 4.2 - 2.1i})
}
