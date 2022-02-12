// Can this eliminate single-layer struct?

// RUN: clang %s -O0 -S -emit-llvm -o %t.ll
// RUN: opt -load %builddir/pass/SROAPass%shlibext -scalarrepl-jiawei6 %t.ll -S -o %t.out.ll
// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/property_test.py TestSORA.test_no_struct

struct Ticket {
    int price_per_mile;
    int distance;
};

int get_price(struct Ticket t) {
    return t.price_per_mile * t.distance;
}
