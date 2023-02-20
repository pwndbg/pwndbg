// This binary will exit with a non-zero exit code if the thread is not killed before the main thread exits.

#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void *thread_function(void *arg)
{
    usleep(4000);
    exit(1);
    return NULL;
}

void *useless_thread(void *arg)
{
    while (1) {
        usleep(1000);
    }
    return NULL;
}

void break_here()
{

}

int main()
{
    pthread_t thread;
    int res = pthread_create(&thread, NULL, thread_function, NULL);
    if (res != 0) {
        perror("Thread creation failed");
        exit(EXIT_FAILURE);
    }
    int res2 = pthread_create(&thread, NULL, useless_thread, NULL);
    if (res2 != 0) {
        perror("Thread creation failed");
        exit(EXIT_FAILURE);
    }
    
    break_here();
    usleep(8000);
    
    return 0;
}
