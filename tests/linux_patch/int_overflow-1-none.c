// http://git.kernel.org/linus/b7058842c940ad2c08dd829b21e5c92ebe3b8758
// av7110-2011-0521

// RUN: clang-14 -D __PATCH__ -O0 -Xclang -disable-O0-optnone -emit-llvm -S %s -o %t.ll
// RUN: opt-14 -load-pass-plugin=%builddir/mkint/MiniKintPass.so -passes=mkint-pass -S %t.ll -o %t.out.ll

// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_IR_correct
// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_i_annoted


#include "linux.h"

#define IFNAMSIZ	16
#define SO_BINDTODEVICE	25

int sys_ax25_setsockopt(struct socket *sock, int level, int optname,
#ifndef __PATCH__
	char __user *optval, int optlen)
#else
	char __user *optval, unsigned int optlen)
#endif
{
	char devname[IFNAMSIZ];
	int res = 0;

	if (optlen < sizeof(int))
		return -EINVAL;

	switch (optname) {
	case SO_BINDTODEVICE:
		if (optlen > IFNAMSIZ)
			optlen = IFNAMSIZ;
		if (copy_from_user(devname, optval, optlen)) { // exp: {{size}}
			res = -EFAULT;
			break;
		}
	default:
		res = -ENOPROTOOPT;
	}
	return res;
}
