#include "linux.h"


#define ZERO 0
#define ONE 1
#define TWO 2

u32 div1(u32 n)
{
	return n / ZERO; 
}


u32 div2(u32 n, u8 d)
{
	return n / (d & 0); 
}

u32 div3(u32 n)
{
	return n / (TWO - ONE * 2); 
}

u32 div4(u32 n, u8 d)
{
	return n /  ((d << 1) & 1); 
}