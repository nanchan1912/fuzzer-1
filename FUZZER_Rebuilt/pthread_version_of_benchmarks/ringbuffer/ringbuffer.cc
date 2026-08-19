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

int main(){


}
