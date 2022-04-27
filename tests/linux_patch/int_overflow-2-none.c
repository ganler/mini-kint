// http://git.kernel.org/linus/194b3da873fd334ef183806db751473512af29ce
// agp-2011-2022

// RUN: clang-14 -D __PATCH__ -O0 -Xclang -disable-O0-optnone -emit-llvm -S %s -o %t.ll
// RUN: opt-14 -load-pass-plugin=%builddir/mkint/MiniKintPass.so -passes=mkint-pass -S %t.ll -o %t.out.ll

// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_IR_correct
// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_i_annoted


#include "linux.h"

struct agp_memory {
	size_t	page_count;
};

int __get_num_entries(void);
int __agp_type_to_mask_type(int);
void __writel(size_t);
int agp_num_entries(void);

int sys_agp_generic_remove_memory(struct agp_memory *mem, off_t pg_start, int type)
{
	size_t i;
	int mask_type, num_entries = __get_num_entries();

	if (mem->page_count == 0)
		return 0;

#ifdef __PATCH__
	num_entries = agp_num_entries();
	if (((pg_start + mem->page_count) > num_entries) ||
	    ((pg_start + mem->page_count) < pg_start))
		return -EINVAL;
#endif
	mask_type = __agp_type_to_mask_type(type);
	if (mask_type != 0) {
		/* The generic routines know nothing of memory types */
		return -EINVAL;
	}

	/* AK: bogus, should encode addresses > 4GB */
	for (i = pg_start; i < (mem->page_count + pg_start); i++) { // exp: {{uadd}}
		__writel(i);
	}

	return 0;
}
