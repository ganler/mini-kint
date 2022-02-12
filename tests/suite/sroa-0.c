// Can this it pass a very simple program?

// RUN: clang %s -O0 -S -emit-llvm -o %t.ll
// RUN: opt -load %builddir/pass/SROAPass%shlibext -scalarrepl-jiawei6 %t.ll -S -o %t.out.ll
// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/property_test.py TestSORA.test_no_struct

#include <stdlib.h>

int add(int a, int b) { return a + b; }

int main(int argc , char * argv []) {
    if (argc != 3) {
        return 1;
    }

    int a = atoi(argv[1]), b = atoi(argv[2]);
    return add(a, b);
}
