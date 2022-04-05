#include "linux.h"
#include <stdlib.h>
#include <stdint.h>

#define NEGATIVE_ONE -1

u32 idx1()
{
    u32 arr[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
	return arr[-1]; 
}

u32 idx2()
{
    u32 arr[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
	return arr[10]; 
}

u32 idx3(u32 n)
{
    u32 arr[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    return arr[(n | 0x1) << 4]; //  at least 0x10
}

u32 idx4(u32 n) 
{
    u32 arr[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    return arr[n];
}

u32 idx5()
{
    u32 arr[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    return arr[NEGATIVE_ONE];
}