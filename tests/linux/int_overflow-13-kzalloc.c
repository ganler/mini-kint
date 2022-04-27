// http://git.kernel.org/linus/5591bf07225523600450edd9e6ad258bb877b779
// snd-2010-3442

// RUN: clang-14 -O0 -Xclang -disable-O0-optnone -emit-llvm -S %s -o %t.ll
// RUN: opt-14 -load-pass-plugin=%builddir/mkint/MiniKintPass.so -passes=mkint-pass -S %t.ll -o %t.out.ll

// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_IR_correct
// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_i_annoted


#include "linux.h"

#define MAX_CONTROL_COUNT	1028

struct snd_kcontrol {
	unsigned int count;
};

struct snd_kcontrol_volatile {
	struct snd_ctl_file *owner;
	unsigned int access;
};

struct sys_snd_kcontrol *snd_ctl_new(struct snd_kcontrol *control,
				 unsigned int access)
{
	struct snd_kcontrol *kctl;

#ifdef __PATCH__
	if (control->count > MAX_CONTROL_COUNT)
		return NULL;
#endif
	kctl = kzalloc(sizeof(*kctl) + sizeof(struct snd_kcontrol_volatile) * control->count, GFP_KERNEL); // exp32: {{umul}}
	return kctl;
}
