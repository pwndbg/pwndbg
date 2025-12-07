#include <stdlib.h>
#include <string.h>

void break_here() {};

int main () {
  char* buffer1 = malloc(0x20);
  char* buffer2 = malloc(0x20);
  char* buffer3 = malloc(0x20);
  char* buffer4 = malloc(0x211);
  char* buffer5 = malloc(0x211);

  break_here();

  memset(buffer1, 0xA, 0x20);
  memset(buffer2, 0xB, 0x20);
  memset(buffer3, 0xC, 0x20);
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
