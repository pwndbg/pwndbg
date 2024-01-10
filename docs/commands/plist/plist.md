



# plist

## Description


Dumps the elements of a linked list.

This command traverses the linked list beginning at a given element, dumping its
contents and the contents of all the elements that come after it in the list.
Traversal is configurable and can handle multiple types of linked lists, but will
always stop when a cycle is detected.

The path to the first element can be any GDB expression that evaluates to either
the first element directly, or a to pointer to it. The next element is the name
of the field containing the next pointer, in either the structure itself or in
the structure given by --inner.

An address value may be given with --sentinel that signals the end of the list.
By default, the value used is NULL (0).

If only one field inside each node is desired, it can be printed exclusively by
specifying its name with --field.

This command supports traversing three types of linked lists, classified by how
the next pointer can be found in the structure and what type it is:
    1 - Next pointer is field of structure, type is the same as structure.
    2 - Next pointer is field of inner nested structure, pointed to type is the
        same as outer structure.
    3 - Next pointer is field of inner nested structure, pointed to type is the
        same as inner structure.
Types 2 and 3 require --inner to be specified.

Example 1:

```
struct node {
    int value;
    struct node *next;
};
struct node node_c = { 2, NULL };
struct node node_b = { 1, &node_c };
struct node node_a = { 0, &node_b };
```

pwndbg> plist node_a next
0x4000011050 <node_a>: {
  value = 0,
  next = 0x4000011040 <node_b>
}
0x4000011040 <node_b>: {
  value = 1,
  next = 0x4000011010 <node_c>
}
0x4000011010 <node_c>: {
  value = 2,
  next = 0x0
}

Example 2:

```
struct node_inner_a {
    struct node_inner_a *next;
};
struct inner_a_node {
    int value;
    struct node_inner_a inner;
};
struct inner_a_node inner_a_node_c = { 2, { NULL } };
struct inner_a_node inner_a_node_b = { 1, { &inner_a_node_c.inner } };
struct inner_a_node inner_a_node_a = { 0, { &inner_a_node_b.inner } };
```

pwndbg> plist inner_a_node_a -i inner next
0x4000011070 <inner_a_node_a>: {
  value = 0,
  inner = {
    next = 0x4000011068 <inner_a_node_b+8>
  }
}
0x4000011060 <inner_a_node_b>: {
  value = 1,
  inner = {
    next = 0x4000011028 <inner_a_node_c+8>
  }
}
0x4000011020 <inner_a_node_c>: {
  value = 2,
  inner = {
    next = 0x0
  }
}

Example 3:

```
struct inner_b_node;
struct node_inner_b {
    struct inner_b_node *next;
};
struct inner_b_node {
    int value;
    struct node_inner_b inner;
};
struct inner_b_node inner_b_node_c = { 2, { NULL } };
struct inner_b_node inner_b_node_b = { 1, { &inner_b_node_c } };
struct inner_b_node inner_b_node_a = { 0, { &inner_b_node_b } };
```

pwndbg> plist inner_b_node_a -i inner next
0x4000011090 <inner_b_node_a>: {
  value = 0,
  inner = {
    next = 0x4000011080 <inner_b_node_b>
  }
}
0x4000011080 <inner_b_node_b>: {
  value = 1,
  inner = {
    next = 0x4000011030 <inner_b_node_c>
  }
}
0x4000011030 <inner_b_node_c>: {
  value = 2,
  inner = {
    next = 0x0
  }
}


## Usage:


```bash
usage: plist [-h] [-s SENTINEL] [-i INNER_NAME] [-f FIELD_NAME] path next

```
## Positional Arguments

|Positional Argument|Help|
| :--- | :--- |
|`path`|The first element of the linked list|
|`next`|The name of the field pointing to the next element in the list|

## Optional Arguments

|Short|Long|Default|Help|
| :--- | :--- | :--- | :--- |
|`-h`|`--help`||show this help message and exit|
|`-s`|`--sentinel`|`0`|The address that stands in for an end of list marker in a non-cyclic list (default: %(default)s)|
|`-i`|`--inner`|`None`|The name of the inner nested structure where the next pointer is stored|
|`-f`|`--field`|`None`|The name of the field to be displayed, if only one is desired|
