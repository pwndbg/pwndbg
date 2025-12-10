#include <stddef.h> /* For NULL. */
#include <stdint.h> /* For size_t. */

/* Linked list in which the pointer to the next element in inside the node
 * structure itself. */
struct node {
    int value;
    struct node *next;
};
struct node node_f = { 5, NULL };
struct node node_e = { 4, &node_f };
struct node node_d = { 3, &node_e };
struct node node_c = { 2, &node_d };
struct node node_b = { 1, &node_c };
struct node node_a = { 0, &node_b };

/* Linked list in which the nodes are inner structures of a larger structure. */
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

/* Linked list in which the pointer to the next element is nested inside the
 * structure. */
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

/* Linked list using size_t for next pointer to test pointer-sized integer support. */
struct size_t_node {
    int value;
    size_t next;
};
struct size_t_node size_t_node_c = { 42, 0 };
struct size_t_node size_t_node_b = { 21, (size_t)&size_t_node_c };
struct size_t_node size_t_node_a = { 10, (size_t)&size_t_node_b };


void break_here(void) {}
int main(void)
{
    break_here();
    return 0;
}

