#include <pthread.h>

struct MyStruct {
    int matrix[4][4];
    int done;
};

struct MyStruct s = {{{0}}, 0};

void *thread_1(void *arg) {
    for (int j = 0; j < 4; j++) {
        s.matrix[j][0] = j;
    }
    return NULL;
}

void *thread_2(void *arg) {
    for (int j = 0; j < 4; j++) {
        s.matrix[j][1] = j + 10;
    }
    s.done = 1;
    return NULL;
}

int main() {
    pthread_t t1, t2;

    pthread_create(&t1, NULL, thread_1, NULL);
    pthread_create(&t2, NULL, thread_2, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
}