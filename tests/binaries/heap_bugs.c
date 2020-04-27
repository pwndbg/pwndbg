#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/* copy-paste from malloc.c */
# define INTERNAL_SIZE_T size_t
#define SIZE_SZ (sizeof (INTERNAL_SIZE_T))
#define MALLOC_ALIGNMENT (2 * SIZE_SZ < __alignof__ (long double) \
              ? __alignof__ (long double) : 2 * SIZE_SZ)

typedef struct malloc_chunk {
    INTERNAL_SIZE_T      prev_size;  /* Size of previous chunk (if P == 0).  */
    INTERNAL_SIZE_T      size;       /* Size in bytes, including overhead. 3LSB: N,M,P*/
    /* A(NON_MAIN_ARENA), M(IS_MMAPPED), P(PREV_INUSE) */

    struct malloc_chunk* fd;         /* double links -- used only if free. */
    struct malloc_chunk* bk;

    /* Only used for large blocks: pointer to next larger size.  */
    struct malloc_chunk* fd_nextsize; /* double links -- used only if free. */
    struct malloc_chunk* bk_nextsize;
} malloc_chunk;

/* common heap setup */
#define setup_heap char *a = malloc(50); \
char *b = malloc(50); \
char *c = malloc(50); \
char *d = malloc(4000); \
char *e = malloc(4000); \
char *f = malloc(4000); \
char *g = malloc(4000); \
malloc_chunk *a_real = (malloc_chunk*)(a - 2*SIZE_SZ); \
malloc_chunk *b_real = (malloc_chunk*)(b - 2*SIZE_SZ); \
malloc_chunk *c_real = (malloc_chunk*)(c - 2*SIZE_SZ); \
malloc_chunk *d_real = (malloc_chunk*)(d - 2*SIZE_SZ); \
malloc_chunk *e_real = (malloc_chunk*)(e - 2*SIZE_SZ); \
malloc_chunk *f_real = (malloc_chunk*)(f - 2*SIZE_SZ); \
malloc_chunk *g_real = (malloc_chunk*)(g - 2*SIZE_SZ); \
int *tmp; \
int tmp2, tmp3; \
printf("a=%p\nb=%p\nc=%p\nd=%p\ne=%p\nf=%p\ng=%p\n", a, b, c, d, e, f, g);

/*
Every function MUST have two comments: "break1" and "break2"
One after setup, second just before line triggering the bug 
*/

void invalid_pointer_overflow() {
    // free(): invalid pointer
    setup_heap
    // break1

    tmp2 = a_real->size;
    a_real->size = 0xffffffffffffff00;
    // break2
    free(a);
    a_real->size = tmp2;
}

void invalid_pointer_misaligned() {
    // free(): invalid pointer
    setup_heap
    // break1

    // break2
    free(a+2);
}

void invalid_size_minsize() {
    // free(): invalid size
    setup_heap
    // break1

    tmp2 = a_real->size;
    a_real->size = 8;
    // break2
    free(a);
    a_real->size = tmp2;
}

void invalid_size_misaligned() {
    // free(): invalid size
    setup_heap
    // break1

    tmp2 = a_real->size;
    a_real->size = 24;
    // break2
    free(a);
    a_real->size = tmp2;
}

void invalid_next_size_fast() {
    // free(): invalid next size (fast)
    setup_heap
    // break1

    tmp2 = a_real->size;
    tmp3 = a[32 - 2*SIZE_SZ + SIZE_SZ];
    a_real->size = 32;
    a[32 - 2*SIZE_SZ + SIZE_SZ] = (size_t*)3;
    // break2
    free(a);
    a[32 - 2*SIZE_SZ + SIZE_SZ] = (size_t*)tmp3;
    a_real->size = tmp2;
}

void double_free_tcache() {
    // free(): double free detected in tcache 2
    setup_heap
    // break1

    free(a);
    // break2
    free(a);
}

void double_free_fastbin() {
    // double free or corruption (fasttop)
    setup_heap
    // break1

    void *ptrs[10];
    for (int i = 0; i < 10; ++i)
        ptrs[i] = malloc(50);
    for (int i = 0; i < 10; ++i)
        free(ptrs[i]);

    free(a);
    // break2
    free(a);
}

void invalid_fastbin_entry() {
    // invalid fastbin entry (free)
    // not working, dunno why
    // maybe because of 'have_lock == 0'
    setup_heap
    // break1

    void *ptrs[10];
    for (int i = 0; i < 10; ++i)
        ptrs[i] = malloc(50);
    for (int i = 0; i < 10; ++i)
        free(ptrs[i]);

    free(a);
    a_real->size = 88;
    // break2
    free(c);
}

void double_free_or_corruption_top() {
    // double free or corruption (top)
    setup_heap
    // break1

    malloc_chunk *top_chunk_real = (malloc_chunk*) (((size_t)c_real + c_real->size) & (~7));
    char *top_chunk = (char*) ((size_t)top_chunk_real + 2*SIZE_SZ);
    // break2
    free(top_chunk);
}

void double_free_or_corruption_out() {
    // double free or corruption (out)
    setup_heap
    // break1

    d_real->size = 0xffffff00;
    // break2
    free(d);
}

void double_free_or_corruption_prev() {
    // double free or corruption (!prev)
    setup_heap
    // break1

    e_real->size &= ~1;
    // break2
    free(d);
}

void invalid_next_size_normal() {
    // free(): invalid next size (normal)
    setup_heap
    // break1

    e_real->size = 1;
    // break2
    free(d);
}

void corrupted_consolidate_backward() {
    // corrupted size vs. prev_size while consolidating
    setup_heap
    // break1

    free(d);
    d_real->size = 0xaa;
    // break2
    free(e);
}

void corrupted_unsorted_chunks() {
    // free(): corrupted unsorted chunks
    setup_heap
    // break1

    free(d); // it goes to unsorted
    d_real->bk = a_real;
    // break2
    free(f);
}


int main(int argc, char const *argv[]) {
    setvbuf(stdout, NULL, _IONBF, 0);

    if (argc < 2) {
        printf("Usage: %s bug_to_trigger\n", argv[0]);
        return 1;
    }

    int choice;
    sscanf(argv[1], "%d", &choice);
    switch(choice) {
        case 1: invalid_pointer_overflow(); break;
        case 2: invalid_pointer_misaligned(); break;
        case 3: invalid_size_minsize(); break;
        case 4: invalid_size_misaligned(); break;
        case 5: double_free_tcache(); break;
        case 6: invalid_next_size_fast(); break;
        case 7: double_free_fastbin(); break;
        case 8: invalid_fastbin_entry(); break;
        case 9: double_free_or_corruption_top(); break;
        case 10: double_free_or_corruption_out(); break;
        case 11: double_free_or_corruption_prev(); break;
        case 12: invalid_next_size_normal(); break;
        case 13: corrupted_consolidate_backward(); break;
        case 14: corrupted_unsorted_chunks(); break;
        default: printf("Unknown\n");
    }
    
    puts("END");
    return 0;
}