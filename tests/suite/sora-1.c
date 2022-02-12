// RUN: clang %s -S -emit-llvm -o %t.ll
// RUN: opt -enable-new-pm=0 -load ../../build/SROA/SROAPass.so --scalarrepl-jiawei6 %t.ll -S -o %t.out.ll
// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 -m unittest property_test.TestSORA.test_no_struct

struct Ticket {
    int price_per_mile;
    int distance;
    int id;
};

int get_price(struct Ticket t) {
    return t.price_per_mile * t.distance;
}
