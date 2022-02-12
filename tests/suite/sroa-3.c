// Can this eliminate 10-layer struct?

// RUN: clang %s -O0 -S -emit-llvm -o %t.ll
// RUN: opt -load %builddir/pass/SROAPass%shlibext -scalarrepl-jiawei6 %t.ll -S -o %t.out.ll
// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/property_test.py TestSORA.test_no_struct

struct MAGIC {
  struct {
    struct {
      struct {
        struct {
          struct {
            struct {
              struct {
                struct {
                  struct {
                    float lmao;
                  } i;
                } h;
              } g;
            } f;
          } e;
        } d;
      } c;
    } b;
  } a;
};

float get_your_magic(struct MAGIC* m) {
    return m->a.b.c.d.e.f.g.h.i.lmao + 0.;
}
