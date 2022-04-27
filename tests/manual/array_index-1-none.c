// RUN: clang-14 -O0 -Xclang -disable-O0-optnone -emit-llvm -S %s -o %t.ll
// RUN: opt-14 -load-pass-plugin=%builddir/mkint/MiniKintPass.so -passes=mkint-pass -S %t.ll -o %t.out.ll

// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_IR_correct
// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_i_annoted

#include <stdint.h>
#include <stdlib.h>

uint32_t arr[] = { 1, 2, 3, 4, 5, 6, 7, 8, 9, 10 };

void* sys_idx(uint32_t n)
{
    return malloc(arr[(n & 0x1) << 2]); //  at most 4
}
