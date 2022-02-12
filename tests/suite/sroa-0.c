// RUN: clang %s -o %t

// Some trivial code to test the testing infra.
#include <stdlib.h>

int add(int a, int b) { return a + b; }

int main(int argc , char * argv []) {
    if (argc != 3) {
        return 1;
    }

    int a = atoi(argv[1]), b = atoi(argv[2]);
// CHECK: and
    return add(a, b);
}
