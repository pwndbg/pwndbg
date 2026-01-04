#include <stdlib.h>
#include <string.h>

void break_here() {};

int main () {
  // In some environments (e.g. on fedora 41), musl will allocate a slot with a string like
  // "/usr/x86_64-linux-musl/lib64" while on some environments (like archlinux) this string
  // won't be allocated at all (it seems the `sys_path` symbol points to this string). We make
  // sure to allocate 0x50 so we don't end up in the same group as that string to have consistent
  // tests. We also need to be careful about slots with slack because they may bring indeterminism
  // (e.g. between the static and dynamic run).
  char* buffer1 = malloc(0x50);
  char* buffer2 = malloc(0x50);
  char* buffer3 = malloc(0x50);
  char* buffer4 = malloc(0x211);
  char* buffer5 = malloc(0x211);

  break_here();

  memset(buffer1, 0xA, 0x50);
  memset(buffer2, 0xB, 0x50);
  memset(buffer3, 0xC, 0x50);
  memset(buffer4, 0xD, 0x211);
  memset(buffer5, 0xE, 0x211);

  break_here();

  free(buffer1);
  free(buffer2);

  break_here();

  free(buffer3);
  free(buffer4);
  free(buffer5);

  break_here();

  return 0;
}
