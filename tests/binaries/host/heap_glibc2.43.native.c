#include <malloc.h>
#include <pthread.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>

#define INTERNAL_SIZE_T size_t
#define SIZE_SZ (sizeof(INTERNAL_SIZE_T))
#define CHUNK_HDR_SZ (2 * SIZE_SZ)
#define mem2chunk(mem) ((void *)(mem) - CHUNK_HDR_SZ)

void *allocated_chunk = NULL;
void *tcache_chunk = NULL;
void *tcache_large_chunk = NULL;
void *small_chunk = NULL;
void *large_chunk = NULL;
void *unsorted_chunk = NULL;

static void break_here(void) {}
static void break_step(void) {}

static void heap_layout(void) {
    void *tcache_large1 = malloc(0x7f0);
    void *tcache_large2 = malloc(0x900);
    void *tcache_large3 = malloc(0x410);
    free(tcache_large1);
    free(tcache_large2);
    free(tcache_large3);
    tcache_large_chunk = mem2chunk(tcache_large1);
    break_step();

    void *tcache = malloc(0x58);
    free(tcache);
    tcache_chunk = mem2chunk(tcache);

    void *small = malloc(0x110);
    (void)malloc(1); // prevent from being merged by top chunk
    small_chunk = mem2chunk(small);

    void *large = malloc(0x500);
    (void)malloc(1);
    large_chunk = mem2chunk(large);

    void *unsorted = malloc(0x600);
    (void)malloc(1);
    unsorted_chunk = mem2chunk(unsorted);

    (void)realloc(small, 0x120);
    (void)realloc(large, 0x510);
    void *allocated = realloc(unsorted, 0x610);

    allocated_chunk = mem2chunk(allocated);
}

void *thread_func(void *x) {
    malloc(0x20);  // trigger another arena allocation
    break_here();

    heap_layout();
    break_here();

    return x;
}

int main(void) {
    heap_layout();
    break_here();

    pthread_t thread;
    pthread_create(&thread, NULL, thread_func, NULL);
    pthread_join(thread, NULL);
    return 0;
}
