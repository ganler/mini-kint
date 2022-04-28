// http://git.kernel.org/linus/44b0052c5cb4e75389ed3eb9e98c29295a7dadfb

// RUN: clang-14 -O0 -Xclang -disable-O0-optnone -emit-llvm -S %s -o %t.ll
// RUN: opt-14 -load-pass-plugin=%builddir/mkint/MiniKintPass.so -passes=mkint-pass -S %t.ll -o %t.out.ll

// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_IR_correct
// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_i_annoted

typedef unsigned int u32;

int __mkint_ann_foo(u32 status, u32 errc)
{
	if (status | 0x1) {
        // always true
		return errc;
	}
	return 0;
}
