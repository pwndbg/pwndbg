/* This program is meant to SEGFAULT on memcpy()
    due to protection key restrictions(man 7 pkeys).
    It relies on the CPU support for PKU, and presence 
    of the pkey syscalls in the host kernel.
    Above could be checked with:
    $ grep pku /proc/cpuinfo
 */

#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <unistd.h>

// Protection key access rights
#ifndef PKEY_DISABLE_ACCESS
#define PKEY_DISABLE_ACCESS 0x1
#endif
#ifndef PKEY_DISABLE_WRITE
#define PKEY_DISABLE_WRITE  0x2
#endif

int pkey_alloc(unsigned int flags, unsigned int access_rights);
int pkey_mprotect(void *addr, size_t len, int prot, int pkey);
int pkey_free(int pkey);

int main() {
    size_t page_size = sysconf(_SC_PAGESIZE);
    void *page = mmap(NULL, page_size, 
                      PROT_READ | PROT_WRITE | PROT_EXEC,
                      MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    
    if (page == MAP_FAILED) {
        perror("mmap failed");
        return 1;
    }

    unsigned char data[] = {0x41};
    int pkey = pkey_alloc(0, PKEY_DISABLE_WRITE);
    pkey_mprotect(page, page_size, PROT_READ|PROT_WRITE, pkey);
    memcpy(page, data, sizeof(data));
    
    return 0;
}
