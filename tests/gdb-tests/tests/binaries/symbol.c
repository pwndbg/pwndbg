#include <stdio.h>
#include <stdlib.h>

// override static `main_arena` from libc.so.6
unsigned int main_arena = 0x1337;

// override `free` from libc.so.6
void free(void*) {}

enum pageflags {
	PG_locked,
	PG_writeback,
	PG_referenced,
	PG_uptodate,
	PG_dirty,
	PG_lru,
	PG_head,  // 0x6 == lookup_symbol("PG_head").dereference()
	PG_waiters,
	PG_active,
	PG_workingset,
	PG_owner_priv_1,
	PG_owner_2,
	PG_arch_1,
};

typedef struct {
    int id;
    char name[50];
} FooType;

struct {
    int id;
    char name[50];
} BarValue;

typedef enum {
    STATUS_OK = 0,
    STATUS_ERROR = 1,
    STATUS_UNKNOWN = 2
} Status;

void break_here() {
    int free = 0xdeadbeef;  // local variable
}

// TODO: test mangled symbols?

int main() {
    int free = 0x2137;  // local variable
    break_here();

    int *allocated_memory = (int *)malloc(sizeof(int));
    if (allocated_memory == NULL) {
        printf("Memory allocation failed!\n");
        return 1;
    }
}
