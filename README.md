## Project 1: SROA

Assignment description [here](https://charithm.web.illinois.edu/cs526/sp2022/cp1.pdf).

### Features

- [x] SROA for safe structure types;
- [ ] (BONUS) SROA for safe array types;
- [x] Automated compile and testing infrastructure (learned from [here](https://github.com/banach-space/llvm-tutor));

### Test and Compile

```shell
mkdir -p build && cd build
pip install lit # Or if you don't have root: pip install --user lit
# Here LLVM_ROOT is the root of the whole build dir not just cmake dir;
# You can use (/path/to/your)`llvm-config --prefix` to find that;
# The LLVM version should be LLVM 8.0.1;
cmake .. -DCMAKE_BUILD_TYPE=Debug -DLLVM_ROOT=/path/to/LLVM_ROOT
make check # Automaticall run test cases;
```

### Description of tests

We use [`lit`](https://llvm.org/docs/CommandGuide/lit.html) to run testing scripts to check:

- Can the c source be compiled?
- Can the pass successfully be loaded and executed by `opt`?
- Can the output LLVM IR satisfy several properties in `tests/property_test.py`?
    - e.g., no unsafe struct allocas;

1. `tests/suite/sroa-0.c`: Can this pass a very simple program?
2. `tests/suite/sroa-1.c`: Can this eliminate single-layer struct?
3. `tests/suite/sroa-2.c`: Can this eliminate 2-layer struct?
3. `tests/suite/sroa-3.c`: Can this eliminate 10-layer struct?
