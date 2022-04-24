// http://code.google.com/p/chromium/issues/detail?id=117656

#include <stddef.h>

typedef unsigned int u32;
typedef unsigned int T;

static u32 ComputeMaxResults(size_t size_of_buffer) {
    // size_of_buffer may be smaller than sizeof(u32), should compare with sizeof(T) before use
	return (size_of_buffer - sizeof(u32)) / sizeof(T); 

}

size_t ComputeSize(size_t num_results);

void *GetAddressAndCheckSize(u32);

void *HandleGetAttachedShaders(u32 result_size)
{
	u32 max_count = ComputeMaxResults(result_size);
	return GetAddressAndCheckSize(ComputeSize(max_count));
}