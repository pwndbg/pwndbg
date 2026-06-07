// Minimal probe for the bionic (Android libc) test harness.
//
// Built fully static against the Android NDK by Dockerfile.bionic-test-libs (one
// binary per API level). A static bionic binary embeds its own startup and runs
// on stock x86_64 Linux, so it launches under gdb in CI without an Android device
// or emulator. The tests break on break_here() to confirm it runs and reaches a
// user breakpoint.

#include <stdlib.h>

void break_here(void) {}

int main(void) {
    // malloc() so a future bionic heap provider would have allocator state to
    // inspect; today the test only checks the binary runs + its API note.
    void *p = malloc(64);
    break_here();
    free(p);
    return 0;
}
