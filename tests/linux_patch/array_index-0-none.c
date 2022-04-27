// http://git.kernel.org/linus/cb26a24ee9706473f31d34cc259f4dcf45cd0644
// av7110-2011-0521

// RUN: clang-14 -D __PATCH__ -O0 -Xclang -disable-O0-optnone -emit-llvm -S %s -o %t.ll
// RUN: opt-14 -load-pass-plugin=%builddir/mkint/MiniKintPass.so -passes=mkint-pass -S %t.ll -o %t.out.ll

// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_IR_correct
// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_i_annoted


#include "linux.h"

#define CA_CI				1
#define CA_CI_LINK			2
#define FW_CI_LL_SUPPORT(arm_app)	((arm_app) & 0x80000000)

typedef struct ca_slot_info_t {
	int num;
	int type;
	unsigned int flags;
} ca_slot_info_t;

struct av7110 {
	u32		arm_app;
	ca_slot_info_t	ci_slot[2];
};

int sys_dvb_ca_ioctl(struct av7110 *av7110, void *parg)
{
	ca_slot_info_t *info = (ca_slot_info_t *)parg;

#ifndef __PATCH__
	if (info->num > 1)
		return -EINVAL;
#else
	if (info->num < 0 || info->num > 1)
		return -EINVAL;
#endif
	av7110->ci_slot[info->num].num = info->num; // exp: {{array}}
	av7110->ci_slot[info->num].type = FW_CI_LL_SUPPORT(av7110->arm_app) ?
						CA_CI_LINK : CA_CI;
	memcpy(info, &av7110->ci_slot[info->num], sizeof(ca_slot_info_t));
	return 0;
}
