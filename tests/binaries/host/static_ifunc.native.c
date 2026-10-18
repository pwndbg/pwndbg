// Linked without libc so that it does not depend on the host's libc.a. The GOT slot of
// get_one gets an IRELATIVE relocation in a section with no symbol table, as in static glibc
// binaries that are stripped or linked with binutils 2.44. Nothing applies the relocation, so
// the program is only meant to be inspected.

static int one(void) {
    return 1;
}

static int (*resolve_one(void))(void) {
    return one;
}

int get_one(void) __attribute__((ifunc("resolve_one")));

void _start(void) {
    get_one();
}
