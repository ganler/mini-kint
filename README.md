# Mini KINT

Implementing the essential functionalities of [KINT (OSDI'12)](https://www.usenix.org/system/files/conference/osdi12/osdi12-final-88.pdf) using LLVM-14.

## Quick Start

```shell
mkdir -p build && cd build
# Recommend to remove VSCode's C++ plugin and use its ClangD plugin.
cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=1
```

## Run Test

Run unit test and get raw output of LLVM-lit
```shell
cd build
make check
```

Run unit test and get analysis of the test result
```shell
cd build
make check &> test.log
LOG=test.log python3 ../tests/statistics.py
```

Add your own test cases:

Put your c code test file under `tests/manual` and add following comments in the header of the new test file to trigger automatic testing.

```c
// RUN: clang-14 -O0 -Xclang -disable-O0-optnone -emit-llvm -S %s -o %t.ll
// RUN: opt-14 -load-pass-plugin=%builddir/mkint/MiniKintPass.so -passes=mkint-pass -S %t.ll -o %t.out.ll

// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_IR_correct
// RUN: BEFORE=%t.ll AFTER=%t.out.ll python3 %testdir/llvm_lite.py TestMKint.test_i_annoted
```

Then use the same commands used in running unit tests.

## Worklist

- [x] (Basic::Logger) add logger library for debugging and checking;
- [x] (Basic::Z3) integrate Z3 environment in CMake;
- [x] (Feature::TaintAnalysis) Taint/sink annotation and broadcasting (WIP)
  - [x] Taint source and sink mark;
  - [x] Taint broadcasting;
- [x] Per-function range analysis;
  - [x] Backedge analysis;
  - [x] Binary operator;
  - [x] Branch handling;
  - [x] Unary operator;
  - [x] Casting (if have time);
- [x] Cross-function range analysis;
- [x] Constraint solving;
- [x] Error type marking;

## Bound checking

Consider the following cases for all integer expressions.

- [x] **overflow**: observe if *expr > MAXLIM or expr < MINLIM*;
- [x] **div-by-zero**: observe if *div(x, y) that y == 0*;
- [x] **shift**: observe if *shift(a, b) that b >= nbits*;
- [x] **array index**: observe if *arr\[idx\] that idx < 0*;
- [x] **impossible branch**: e.g., ask a uint to be smaller than 0;

Use SMT solver to determine if these are possible and mark plausible ones (**the solution must be related to observable variables**).

## Range analysis (interval analysis)

Find out **observable** variables outside of current functions:

- Function arguments;
- Function return value;
- Global variables;
- Range of observable variables for each block.

Analyze their ranges and apply it in eventual solving.

## Taint Analysis

Is this bug related to **untrusted input**.

- **Taint sources**: arguments of functions whose names start with `sys_` or `__mkint_ann_`.
- **Sinks**: `kmalloc:0`, `kzalloc:0`, `vmalloc:0`, etc.

## Known Issues

**(M1-LLVM-13-Homebrew)** For LLVM-13 installed from Homebrew M1 Monterey stable, the program will crash on `ConstantRange::extendSigned` but it is fine on Linux machines.
This looks like a LLVM bug.