// http://git.kernel.org/linus/252a52aa4fa22a668f019e55b3aac3ff71ec1c29
// pktcdvd-2010-3437

// RUN: clang-14 -D __PATCH__ -O0 -Xclang -disable-O0-optnone -emit-llvm -S %s -o %t.ll
// RUN: opt-14 -load-pass-plugin=%builddir/mkint/MiniKintPass.so -passes=mkint-pass -S %t.ll -o %t.out.ll

// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_IR_correct
// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_i_annoted


#include "linux.h"

#define MAX_WRITERS		8

struct pkt_ctrl_command {
	u32 command;
	u32 dev_index;
	u32 dev;
	u32 pkt_dev;
	u32 num_devices;
	u32 padding;
};

struct block_device {
	dev_t			bd_dev;
};

struct pktcdvd_device {
	struct block_device	*bdev;
	dev_t			pkt_dev;
};

struct pktcdvd_device *pkt_devs[MAX_WRITERS];

#ifndef __PATCH__
static struct pktcdvd_device *pkt_find_dev_from_minor(int dev_minor)
#else
static struct pktcdvd_device *pkt_find_dev_from_minor(unsigned int dev_minor)
#endif
{
	if (dev_minor >= MAX_WRITERS)
		return NULL;
	return pkt_devs[dev_minor]; // exp: {{array}}
}

void sys_pkt_get_status(struct pkt_ctrl_command *ctrl_cmd)
{
	struct pktcdvd_device *pd;

	pd = pkt_find_dev_from_minor(ctrl_cmd->dev_index);
	if (pd) {
		ctrl_cmd->dev = new_encode_dev(pd->bdev->bd_dev);
		ctrl_cmd->pkt_dev = new_encode_dev(pd->pkt_dev);
	} else {
		ctrl_cmd->dev = 0;
		ctrl_cmd->pkt_dev = 0;
	}
	ctrl_cmd->num_devices = MAX_WRITERS;
}
