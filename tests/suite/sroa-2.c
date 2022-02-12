// Can this eliminate 2-layer struct?

// RUN: clang %s -O0 -S -emit-llvm -o %t.ll
// RUN: opt -load %builddir/pass/SROAPass%shlibext -scalarrepl-jiawei6 %t.ll -S -o %t.out.ll
// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/property_test.py TestSORA.test_no_struct

struct Ticket {
    int price_per_mile;
    int distance;
};

struct Combo {
    struct Ticket ticket;
    int service_fee;
};

int get_price(struct Combo c) {
    return c.ticket.price_per_mile * c.ticket.distance + c.service_fee;
}
