#include <pthread.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

void *thread_function(void *arg) {
  free(malloc(0x20));
  sleep(100);
  return NULL;
}

int main(void) {
  pthread_t thread;
  pthread_create(&thread, NULL, thread_function, NULL);
  pthread_exit(NULL);
  return 0;
}
