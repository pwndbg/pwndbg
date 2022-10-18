/* For testing the malloc_chunk command.
 *
 * Move chunks into each bin type so that the test can run the malloc_chunk command on each different type of free chunk.
 */

#include <stdlib.h>
#include <pthread.h>

#define INTERNAL_SIZE_T size_t
#define SIZE_SZ (sizeof (INTERNAL_SIZE_T))
#define CHUNK_HDR_SZ (2 * SIZE_SZ)
#define mem2chunk(mem) ((void*)(mem) - CHUNK_HDR_SZ)

void break_here(void) {}
void configure_heap_layout(void);
void* thread_func(void*);

void* allocated_chunk = NULL;
void* tcache_chunk = NULL;
void* fast_chunk = NULL;
void* small_chunk = NULL;
void* large_chunk = NULL;
void* unsorted_chunk = NULL;

int main(void)
{
    configure_heap_layout();

    break_here();

    pthread_t thread;
    pthread_create(&thread, NULL, thread_func, NULL);
    pthread_join(thread, NULL);
}

void configure_heap_layout(void)
{
    void* chunks[6] = {0};

    // Request 8 fastbin-sized chunks, free these later to populate both the tcache (if present) and a fastbin.
    for (int i=0; i<6; i++)
    {
        chunks[i] = malloc(0x18);
    }

    void* tcache_ = malloc(0x18);
    void* fast = malloc(0x18);

    void* remainder_me = malloc(0x418);
    malloc(0x18);

    void* large = malloc(0x418);
    malloc(0x18);

    void* unsorted = malloc(0x418);
    malloc(0x18);

    // Populate 0x200 smallbin & 0x400 largebin.
    // Use remaindering to avoid tcache (if present).
    free(remainder_me);
    void* before_remainder = malloc(0x208);
    free(large);
    malloc(0x428);

    // Populate the unsortedbin.
    free(unsorted);

    // Populate 0x20 tcachebin (if present) & fastbin.
    for (int i=0; i<6; i++)
    {
        free(chunks[i]);
    }

    free(tcache_);
    free(fast);

    allocated_chunk = mem2chunk(remainder_me);
    tcache_chunk = mem2chunk(tcache_);
    fast_chunk = mem2chunk(fast);
    small_chunk = mem2chunk(before_remainder + 0x210);
    large_chunk = mem2chunk(large);
    unsorted_chunk = mem2chunk(unsorted);
}

void* thread_func(void* args)
{
    // Initialize a 2nd arena by allocating any size chunk.
    malloc(0x18);
    break_here();

    configure_heap_layout();
    break_here();

    pthread_exit(NULL);
}
