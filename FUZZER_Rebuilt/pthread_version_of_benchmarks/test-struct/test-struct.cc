#include <pthread.h>

struct MyStruct {
    int matrix[10][10][10];
    int val1;
    int val2;
};

struct MyStruct s = {{{0}}, 0, 0};

void *thread_1(void *arg) {
    for (int j = 0; j < 10; j++) {
        s.matrix[j][0][0] = j;
    }
    s.val1 = 42;
    return NULL;
}

void *thread_2(void *arg) {
    for (int j = 0; j < 10; j++) {
        s.matrix[j][0][0] = j + 10;
        s.matrix[j][1][1] = j + 20;
    }
    int local_val = s.val1;
    return NULL;
}

void *thread_3(void *arg) {
    for (int j = 0; j < 10; j++) {
        s.matrix[j][1][1] = j + 30;
    }
    s.val2 = 100;
    return NULL;
}

int main() {
    pthread_t t1, t2, t3;

    pthread_create(&t1, NULL, thread_1, NULL);
    pthread_create(&t2, NULL, thread_2, NULL);
    pthread_create(&t3, NULL, thread_3, NULL);

    pthread_join(t1, NULL);
    pthread_join(t2, NULL);
    pthread_join(t3, NULL);
}