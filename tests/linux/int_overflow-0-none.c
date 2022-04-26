// http://git.kernel.org/linus/194b3da873fd334ef183806db751473512af29ce
// agp-2011-1745

// RUN: clang-14 -O0 -Xclang -disable-O0-optnone -emit-llvm -S %s -o %t.ll
// RUN: opt-14 -load-pass-plugin=%builddir/mkint/MiniKintPass.so -passes=mkint-pass -S %t.ll -o %t.out.ll

// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_IR_correct
// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_i_annoted


#include "linux.h"

struct agp_memory {
	size_t	page_count;
};

int __get_num_entries(void);
int __page_empty(off_t);

int agp_generic_insert_memory(struct agp_memory * mem, off_t pg_start)
{
	int num_entries = __get_num_entries();
	off_t j;

	if (mem->page_count == 0)
		return 0;

	if (num_entries < 0) num_entries = 0;

#ifndef __PATCH__
	/* AK: could wrap */
	if ((pg_start + mem->page_count) > num_entries)
#else
	if (((pg_start + mem->page_count) > num_entries) ||
	    ((pg_start + mem->page_count) < pg_start))
#endif
		return -EINVAL;

	j = pg_start;

	while (j < (pg_start + mem->page_count)) { // exp: {{uadd}}
		if (!__page_empty(j))
			return -EBUSY;
		j++;
	}

	return 0;
}
