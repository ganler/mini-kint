// http://git.kernel.org/linus/0f22072ab50cac7983f9660d33974b45184da4f9

#include "linux.h"

#define SEMOPM		32

struct sembuf {
	unsigned short	sem_num;
	short		sem_op;
	short		sem_flg;
};

long sys_oabi_semtimedop(unsigned nsops)
{
	struct sembuf *sops;

#ifndef __PATCH__
	if (nsops < 1)
#else
	if (nsops < 1 || nsops > SEMOPM)
#endif
		return -EINVAL;
	sops = kmalloc(sizeof(*sops) * nsops, GFP_KERNEL); // exp32: {{umul}}
	if (!sops)
		return -ENOMEM;
	return 0;
}
