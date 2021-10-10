#include <stdio.h>
#include <stdint.h>
#include <malloc.h>

#define PADDING_SIZE 0x10
#define TCACHE_SIZE 0x20
#define TCACHE_COUNT 0x7
#define FASTBIN_SIZE TCACHE_SIZE
#define FASTBIN_COUNT 0x4
#define SMALLBIN_SIZE 0x200
#define SMALLBIN_COUNT 0x3
#define LARGEBIN_SIZE 0x500
#define LARGEBIN_COUNT 0x3

// for export only
const size_t padding_size = PADDING_SIZE;
const size_t tcache_size = TCACHE_SIZE;
const size_t tcache_count = TCACHE_COUNT;
const size_t fastbin_size = FASTBIN_SIZE;
const size_t fastbin_count = FASTBIN_COUNT;
const size_t smallbin_size = SMALLBIN_SIZE;
const size_t smallbin_count = SMALLBIN_COUNT;
const size_t largebin_size = LARGEBIN_SIZE;
const size_t largebin_count = LARGEBIN_COUNT;

int break_id = 0;
void *tcache[TCACHE_COUNT];
void *fastbin[FASTBIN_COUNT];
void *smallbin[SMALLBIN_COUNT + TCACHE_COUNT];
void *largebin[LARGEBIN_COUNT];

void breakpoint()
{
    fprintf(stderr, "Breakpoint #%d\n", ++break_id);
    return;
}

void alloc_chunks()
{
    void *padding;
    for (int i = 0; i < TCACHE_COUNT; i++)
        tcache[i] = malloc(TCACHE_SIZE);
    for (int i = 0; i < FASTBIN_COUNT; i++)
        fastbin[i] = malloc(FASTBIN_SIZE);
    for (int i = 0; i < SMALLBIN_COUNT + TCACHE_COUNT; i++)
    {
        smallbin[i] = malloc(SMALLBIN_SIZE);
        // prevent consolidate
        padding = malloc(PADDING_SIZE);
    }
    for (int i = 0; i < LARGEBIN_COUNT; i++)
    {
        largebin[i] = malloc(LARGEBIN_SIZE);
        // prevent consolidate
        padding = malloc(PADDING_SIZE);
    }
    breakpoint();
    return;
}

void tcache_test()
{
    for (int i = 0; i < TCACHE_COUNT; i++)
        free(tcache[i]);
    breakpoint();
    return;
}

void fastbin_test()
{
    // tcache is already full, so freed chunk will be put into fastbin
    for (int i = 0; i < FASTBIN_COUNT; i++)
        free(fastbin[i]);
    breakpoint();
    return;
}

void unsortedbin_test()
{
    for (int i = 0; i < SMALLBIN_COUNT + TCACHE_COUNT; i++)
        free(smallbin[i]);
    breakpoint();
    return;
}

void smallbin_test()
{
    void *tmp;
    // trigger unsortedbin consolidate
    tmp = malloc(SMALLBIN_SIZE + 0x10);
    breakpoint();
    return;
}

void largebin_test()
{
    void *tmp;
    for (int i = 0; i < LARGEBIN_COUNT; i++)
        free(largebin[i]);
    tmp = malloc(LARGEBIN_SIZE + 0x10);
    breakpoint();
    return;
}

void breakchains()
{
    *((uint64_t *)(smallbin[TCACHE_COUNT])) = 0xdeadbeef;
    *((uint64_t *)(largebin[0]) + 1) = 0xdeadbeef;
    breakpoint();
}

void initial()
{
    setbuf(stdin, NULL);
    setbuf(stdout, NULL);
    setbuf(stderr, NULL);
    return;
}

int main()
{
    initial();
    alloc_chunks();
    tcache_test();
    fastbin_test();
    unsortedbin_test();
    smallbin_test();
    largebin_test();
    breakchains();
    return 0;
}