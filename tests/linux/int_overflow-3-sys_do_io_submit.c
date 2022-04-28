// http://git.kernel.org/linus/75e1c70fc31490ef8a373ea2a4bea2524099b478
// aio-2010-3067

// RUN: clang-14 -O0 -Xclang -disable-O0-optnone -emit-llvm -S %s -o %t.ll
// RUN: opt-14 -load-pass-plugin=%builddir/mkint/MiniKintPass.so -passes=mkint-pass -S %t.ll -o %t.out.ll

// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_IR_correct
// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_i_annoted

#include "linux.h"

struct iocb;

long sys_do_io_submit(long nr, struct iocb __user *__user *iocbpp)
{
	long ret = 0;

	if (unlikely(nr < 0))
		return -EINVAL;
#ifdef __PATCH__
	if (unlikely(nr > LONG_MAX/sizeof(*iocbpp)))
		nr = LONG_MAX/sizeof(*iocbpp);
#endif
	if (unlikely(!access_ok(VERIFY_READ, iocbpp, (nr*sizeof(*iocbpp))))) // exp: {{umul}}
		return -EFAULT;

	return ret;
}
