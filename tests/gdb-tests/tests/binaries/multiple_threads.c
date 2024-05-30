#include <pthread.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <semaphore.h>

sem_t sem;

void *useless_thread(void *arg)
{
    // signal the semaphore to indicate that the thread has started
    sem_post(&sem);

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

    // Initialize semaphore with count 0 to make sure both threads are started before calling break_here
    sem_init(&sem, 0, 0);

    pthread_t thread1, thread2;
    int res1 = pthread_create(&thread1, NULL, useless_thread, NULL);
    if (res1 != 0) {
        perror("Thread creation failed");
        exit(EXIT_FAILURE);
    }
    int res2 = pthread_create(&thread2, NULL, useless_thread, NULL);
    if (res2 != 0) {
        perror("Thread creation failed");
        exit(EXIT_FAILURE);
    }

    // Wait for both threads to start
    sem_wait(&sem);
    sem_wait(&sem);

    break_here();
    usleep(8000);

    return 0;
}
