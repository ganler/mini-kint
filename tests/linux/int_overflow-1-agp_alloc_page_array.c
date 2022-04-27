// http://git.kernel.org/linus/b522f02184b413955f3bc952e3776ce41edc6355
// agp-2011-1746

// RUN: clang-14 -O0 -Xclang -disable-O0-optnone -emit-llvm -S %s -o %t.ll
// RUN: opt-14 -load-pass-plugin=%builddir/mkint/MiniKintPass.so -passes=mkint-pass -S %t.ll -o %t.out.ll

// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_IR_correct
// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_i_annoted


#include "linux.h"

#ifdef __LP64__
#define SIZE_OF_AGP_MEMORY	104
#else
#define SIZE_OF_AGP_MEMORY	60
#endif

struct agp_memory {
	char ph[SIZE_OF_AGP_MEMORY];
};

void agp_alloc_page_array(size_t size, struct agp_memory *mem);

struct agp_memory *sys_agp_create_user_memory(unsigned long num_agp_pages)
{
	struct agp_memory *new;
	unsigned long alloc_size = num_agp_pages*sizeof(struct page *); // exp: {{umul}}

#ifdef __PATCH__
	if (INT_MAX/sizeof(struct page *) < num_agp_pages)
		return NULL;
#endif
	new = kzalloc(sizeof(struct agp_memory), GFP_KERNEL);
	if (new == NULL)
		return NULL;

	agp_alloc_page_array(alloc_size, new);

	return new;
}
