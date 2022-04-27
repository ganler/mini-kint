// http://git.kernel.org/linus/6a54435560efdab1a08f429a954df4d6c740bddf
// kvm-2009-3638

// RUN: clang-14 -D __PATCH__ -O0 -Xclang -disable-O0-optnone -emit-llvm -S %s -o %t.ll
// RUN: opt-14 -load-pass-plugin=%builddir/mkint/MiniKintPass.so -passes=mkint-pass -S %t.ll -o %t.out.ll

// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_IR_correct
// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_i_annoted


#include "linux.h"

#define KVM_MAX_CPUID_ENTRIES	80

struct kvm_cpuid2 {
	u32 nent;
};

struct kvm_cpuid_entry2 {
	u32 data[10];
};

int sys_kvm_dev_ioctl_get_supported_cpuid(struct kvm_cpuid2 *cpuid,
                                      struct kvm_cpuid_entry2 *entries)
{
	int r;
	struct kvm_cpuid_entry2 *cpuid_entries;

	if (cpuid->nent < 1)
		goto out;
#ifdef __PATCH__
	if (cpuid->nent > KVM_MAX_CPUID_ENTRIES)
		cpuid->nent = KVM_MAX_CPUID_ENTRIES;
#endif
	r = -ENOMEM;
	cpuid_entries = vmalloc(sizeof(struct kvm_cpuid_entry2) * cpuid->nent); // exp32: {{umul}}
	if (!cpuid_entries)
		goto out;
	r = 0;
	vfree(cpuid_entries);
out:
	return r;
}
