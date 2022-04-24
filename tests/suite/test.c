#include <stdint.h>
#include <stddef.h>

uint8_t __mkint_ann_malloc_array_nc(uint8_t n, size_t size)
{
	uint8_t r = n * size;
	void * add = mem_alloc
}


// #include <stdint.h>
// #include <stdlib.h>

// int arr[5] = {
//     1,
//     2,
//     3,
// };

// // int arr = 10;

// uint32_t __mkint_ann_aalloc(uint8_t size) { return size * 4; }

// int __mkint_sink1(uint8_t idx)
// {
//     if (__mkint_ann_aalloc(arr[idx]) == -1)
//         return 10;
//     return 20;
// }