// http://git.kernel.org/linus/0f22072ab50cac7983f9660d33974b45184da4f9
// oabi-2011-1759

// RUN: clang-14 -D __PATCH__ -O0 -Xclang -disable-O0-optnone -emit-llvm -S %s -o %t.ll
// RUN: opt-14 -load-pass-plugin=%builddir/mkint/MiniKintPass.so -passes=mkint-pass -S %t.ll -o %t.out.ll

// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_IR_correct
// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_i_annoted


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
