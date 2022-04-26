// RUN: clang-14 -O0 -Xclang -disable-O0-optnone -emit-llvm -S %s -o %t.ll
// RUN: opt-14 -load-pass-plugin=%builddir/mkint/MiniKintPass.so -passes=mkint-pass -S %t.ll -o %t.out.ll

// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_IR_correct
// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_i_annoted


// http://git.kernel.org/linus/44b0052c5cb4e75389ed3eb9e98c29295a7dadfb
#define BIT(n)		(1UL << (n))

#define PCH_EPASSIVE	BIT(5)
#define PCH_EWARN	BIT(6)

#define PCH_REC		0x00007f00
#define PCH_TEC		0x000000ff

typedef unsigned int u32;

int __mkint_ann_foo(u32 status, u32 errc)
{
	if (status & PCH_EWARN)	{
		if (((errc & PCH_REC) >> 8) > 96)
			return -1;
		if ((errc & PCH_TEC) > 96)
			return -2;
	}
	if (status & PCH_EPASSIVE) {
        // PCH_REC is 0x00007f00, (errc & PCH_REC) >> 8 is at most 0x0000007f (127), so the comparison always be false
		if (((errc & PCH_REC) >> 8) > 127)  
			return -3;
		if ((errc & PCH_TEC) > 127)
			return -4;
	}
	return 0;
}
