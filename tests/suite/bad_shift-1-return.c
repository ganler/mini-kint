#include "linux.h"
#include <stdlib.h>
#include <stdint.h>


#define SHIFT_NEGATIVE -1

u32 shift1(u32 n)
{
	return n << sizeof(u32) * 8; 
}


u32 shift2(u32 n)
{
	return n >> sizeof(u32) * 8; 
}

u32 shift3(u32 n)
{
	return n >> ((sizeof(u32) * 8) & 0x2f); 
}

u8 shift4(u8 n)
{
	return n >> (sizeof(u32) * 8); 
}


