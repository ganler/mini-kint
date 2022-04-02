#include "log.hpp"

#include <z3++.h>

inline void test_smt()
{
    using namespace z3;
    context ctx;
    solver s(ctx);
    expr x = ctx.int_const("x");
    expr y = ctx.int_const("y");

    s.add(x > 0);
    s.add(y > 0);
    s.add(x + y == 2);

    if (sat == s.check()) {
        model m = s.get_model();
        MKINT_LOG() << "x = " << m.eval(x, true) << '\t' << "y = " << m.eval(y, true);
    } else {
        MKINT_CHECK_RELAX(false) << "unsat!";
    }
}