// http://git.kernel.org/linus/44ab8cc56c45ca781371a4a77f35da19cf5db028

// RUN: clang-14 -O0 -Xclang -disable-O0-optnone -emit-llvm -S %s -o %t.ll
// RUN: opt-14 -load-pass-plugin=%builddir/mkint/MiniKintPass.so -passes=mkint-pass -S %t.ll -o %t.out.ll

// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_IR_correct
// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_i_annoted

#define DP_TRAIN_PRE_EMPHASIS_9_5	(3 << 3)
#define DP_TRAIN_VOLTAGE_SWING_1200	(3 << 0)

typedef unsigned char u8;

int __mkint_ann_foo(u8 lane)
{
	u8 lpre = (lane & 0x0c) >> 2; // lane is 8 bit, lane & 00001100 >> 2 is at most 3
	u8 lvsw = (lane & 0x03) >> 0;
	if (lpre == DP_TRAIN_PRE_EMPHASIS_9_5) // CHECK: {{comparison always false}}
		return -1;
	if ((lpre << 3) == DP_TRAIN_PRE_EMPHASIS_9_5)
		return -2;
	if (lvsw == DP_TRAIN_VOLTAGE_SWING_1200)
		return -3;
	return 0;
}
