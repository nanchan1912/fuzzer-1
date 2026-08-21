#include <stdlib.h>
#include <stdio.h>
// #include <threads.h>
#include <pthread.h>

#include "ringbuffer.h"
#include "librace.h"

jnk0le::Ringbuffer<const char*, 256> message;

extern "C" void SysTick_Handler(void)
{
		message.insert("SysTick_Handler");
}

static void* producer_thread(void* arg)
{
	for (int i = 0; i < 5; ++i) {
		SysTick_Handler();
	}
	return NULL;
}

int main(){
	pthread_t producer;
	pthread_create(&producer, NULL, producer_thread, NULL);

	const char* tmp = nullptr;
	int count = 0;
	while (count < 5) {
		if (message.remove(tmp)) {
			count++;
		}
	}

	pthread_join(producer, NULL);
	return 0;
}
