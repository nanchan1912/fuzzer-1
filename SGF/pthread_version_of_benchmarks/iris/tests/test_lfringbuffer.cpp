#include <thread>
#include <string>
#include<cstring>
#include <assert.h>

#include <lfringbuffer.h>
#include <sslfqueue.h>
#include <define.h>

#include <level_logger.h>
#include <file_writer.h>

iris::file_writer writer("./log.txt");
// this creates a logging thread
iris::level_logger g_log(&writer, iris::TRACE);


using namespace iris;
#define ITERATIONS (int) 1000000
lfringbuffer rbuf(1024);
struct buffer_t {
    char * b;
    int    size;
    int    alloc_size;
    int    data;
};
sslfqueue<buffer_t> q;

void recyle() {
    int i = 1;
    while (i <= ITERATIONS) {
        buffer_t b;
        while (!q.poll(b))
            std::this_thread::yield();

        assert(std::stoi(std::string(b.b, b.b + b.size)) == b.data);

        rbuf.release(b.alloc_size);
        ++i;
    }
}

int main(int argc, char const *argv[]) {


    //configure thread level parameters, these should be done before any logging
    // queue size
    g_log.set_thread_queue_size(1024);
    // ring buffer size
    g_log.set_thread_ringbuf_size(20480);
    
    g_log.info("Greetings from %s, bye %d\n", "iris", 0);
    
    //this tells logging thread to persist the data into file and waits
    g_log.sync_and_close();

    char *p1;
    char *p2;
    char *p3;
    assert(512 == rbuf.acquire(512, p1));
    assert(p1);

    assert(256 == rbuf.acquire(256, p2));
    assert(p2);

    assert(p2 - p1 == 512);

    assert(0 == rbuf.acquire(512, p1));

    assert(rbuf.freespace() == 256);

    assert(0 == rbuf.acquire(512, p3));

    rbuf.release(512);

    assert(768 == rbuf.acquire(512, p3));

    printf("rbuf.freespace(): %lu\n", rbuf.freespace());
    assert(rbuf.freespace() == 0);

    rbuf.release(256);
    printf("rbuf.freespace(): %lu\n", rbuf.freespace());
    assert(256 == rbuf.freespace());
    rbuf.release(768);
    printf("rbuf.freespace(): %lu\n", rbuf.freespace());
    assert(1024 == rbuf.freespace());

    std::thread recyler(recyle);

    int i = 1;
    while (i <= ITERATIONS) {
        std::string s(std::to_string(i));

        buffer_t b;
        char *ptr;
        int size;
        while (!(size = rbuf.acquire(s.size(), ptr)))
            std::this_thread::yield();

        b.b = ptr;
        memcpy(b.b, s.c_str(), s.size());
        b.size = s.size();
        b.alloc_size = size;
        b.data = i;

        while (!q.offer(b))
            std::this_thread::yield();
        ++i;
    }



    recyler.join();
    printf("passed\n");
    return 0;
}
