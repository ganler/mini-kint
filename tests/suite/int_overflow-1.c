
#include <stdlib.h>
#include <stdint.h>

void *malloc_array_nc(size_t n, size_t size)
{
	return malloc(n * size);
}

void *malloc_array_0(size_t n, size_t size)
{
	if (size && n > SIZE_MAX / size)
		return NULL;
	return malloc(n * size);
}

void *malloc_array_1(size_t n, size_t size)
{
	if (n && size > SIZE_MAX / n)
		return NULL;
	return malloc(n * size);
}

void *malloc_array_2(size_t n, size_t size)
{
	size_t bytes = n * size;
	if (size && n != bytes / size)
		return NULL;
	return malloc(bytes);
}