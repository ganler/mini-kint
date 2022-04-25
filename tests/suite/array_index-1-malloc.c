#include "linux.h"

void *sys_idx3(u32 n)
{
    u32 arr[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
    return malloc(arr[(n | 0x1) << 4]); //  at least 0x10
}
