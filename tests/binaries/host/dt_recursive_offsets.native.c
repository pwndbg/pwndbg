struct dt3807_inner
{
    int a;
    int b;
};

struct dt3807_outer
{
    int x;
    struct dt3807_inner in;
    int y;
};

struct dt3807_outer global_outer = {
    .x = 0x11,
    .in =
        {
            .a = 0x22,
            .b = 0x33,
        },
    .y = 0x44,
};

void break_here(void) {}

int main(void)
{
    break_here();
    return 0;
}
