#include <assert.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

void break_here(void) {}

#define ADDR (void *)0xcafe0000
#define PGSZ 0x1000

void *xmmap(void *addr, size_t length, int prot, int flags, int fd,
            off_t offset) {
    void *p = mmap(addr, length, prot, flags, fd, offset);
    if (MAP_FAILED == p) {
        printf("Failed to map fixed address at %p\n", (void *)addr);
        perror("mmap");
        exit(EXIT_FAILURE);
    }
    return p;
}

int main(void) {
    // We want to allocate multiple adjacent regions, too confirm that vmmap
    // --gaps detects them properly. So iensure we have adjacent allocation,
    // unmapped holes, as well as some guard page with no permissions.

    uint64_t address = (uint64_t)ADDR;
    void    *p;

    // 2 adjacent pages
    p = xmmap((void *)address, PGSZ, PROT_READ,
              MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    address += PGSZ;
    p = xmmap((void *)address, PGSZ, PROT_READ | PROT_WRITE,
              MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    address += PGSZ;

    // GUARD page
    p = xmmap((void *)address, PGSZ, PROT_NONE,
              MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    mprotect(p, 0x1000, PROT_NONE);
    address += PGSZ;

    p = xmmap((void *)address, PGSZ, PROT_READ | PROT_WRITE | PROT_EXEC,
              MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED, -1, 0);
    address += PGSZ;

    break_here();
}
