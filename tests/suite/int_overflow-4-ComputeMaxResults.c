// http://code.google.com/p/chromium/issues/detail?id=117656

// RUN: clang -O1 -Xclang -disable-O0-optnone -emit-llvm -S %s -o %t.ll
// RUN: opt-14 -load-pass-plugin=%builddir/mkint/MiniKintPass.so -passes=mkint-pass -S %t.ll -o %t.out.ll

// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_IR_correct
// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_i_annoted


#include <stddef.h>

typedef unsigned int u32;
typedef unsigned int T;

static u32 ComputeMaxResults(size_t size_of_buffer) {
    // size_of_buffer may be smaller than sizeof(u32), should compare with sizeof(T) before use
	return (size_of_buffer - sizeof(u32)) / sizeof(T); 

}

size_t __mkint_sink0(size_t num_results);

void *GetAddressAndCheckSize(u32);

void *sys_HandleGetAttachedShaders(u32 result_size)
{
	u32 max_count = ComputeMaxResults(result_size);
	return GetAddressAndCheckSize(__mkint_sink0(max_count));
}