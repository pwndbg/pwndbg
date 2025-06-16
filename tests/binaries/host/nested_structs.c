/* This program initializes some nested C structs.
 * Useful for testing pwndbg commands that operate on structs.
 */

/* Can a command deal with nested typedefs?
 * mydef_outer -> mydef_inner -> int
 */
typedef int mydef_inner;
typedef mydef_inner mydef_outer;

/* Can a command deal with anonymous structs?
 * ISO C11 says anonymous_i & anonymous_j fields should be accessible like this:
 * inner_struct.anonymous_i
 */
struct inner_struct
{
    int inner_a;
    mydef_outer inner_b; // int

    struct
    {
        int anonymous_i;
        int anonymous_j;
    };
};

/* Can a command deal with nested named structs and nested anonymous structs?
 * The anonymous_nested field should be accessible like this:
 * outer_struct.anonymous_nested
 */
struct outer_struct
{
    int outer_x;
    mydef_outer outer_y; // int

    struct inner_struct inner;

    struct
    {
        int anonymous_k;
        int anonymous_l;

        struct
        {
            int anonymous_nested;
        };
    };

    int outer_z;
};

// Set a breakpoint on this function to stop in the important places.
void break_here(void) {}

struct outer_struct outer;

int main(void)
{
    // Initialize outer_struct fields with arbitrary values.
    outer.outer_x = 1;
    outer.outer_y = 2;
    outer.outer_z = 5;

    outer.inner.inner_a = 3;
    outer.inner.inner_b = 4;

    outer.inner.anonymous_i = 42;
    outer.inner.anonymous_j = 44;

    outer.anonymous_nested = 100;

    outer.anonymous_k = 82;
    outer.anonymous_l = 84;

    break_here();

    return 0;
}
