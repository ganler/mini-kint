
#include <stdlib.h>
#include <stdint.h>


#define SHIFT_NEGATIVE -1

size_t shift1(size_t n, size_t shift)
{
	return n << shift;
}

size_t shift2(size_t n)
{
	return n << SHIFT_NEGATIVE;
}

