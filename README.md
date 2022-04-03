# Mini KINT

Implementing the essential functionalities of [KINT (OSDI'12)](https://www.usenix.org/system/files/conference/osdi12/osdi12-final-88.pdf) using LLVM-14.

## Quick Start

```shell
mkdir -p build && cd build
# Recommend to remove VSCode's C++ plugin and use its ClangD plugin.
cmake .. -DCMAKE_BUILD_TYPE=Debug -DCMAKE_EXPORT_COMPILE_COMMANDS=1
```

## Worklist

- [x] (Basic::Logger) add logger library for debugging and checking;
- [x] (Basic::Z3) integrate Z3 environment in CMake;
- [ ] (Feature::TaintAnalysis) Taint/sink annotation and broadcasting (WIP);

## Bound checking

Consider the following cases for all integer expressions.

- [ ] **overflow**: observe if *expr > MAXLIM or expr < MINLIM*;
- [ ] **div-by-zero**: observe if *div(x, y) that y == 0*;
- [ ] **shift**: observe if *shift(a, b) that b >= nbits*;
- [ ] **array index**: observe if *arr\[idx\] that idx < 0*;
- [ ] **user-mark**: observe if an user annotation is violated. e.g., data size is marked to be no less than 0.

Use SMT solver to determine if these are possible and mark plausible ones (**the solution must be related to observable variables**).

## Range analysis (interval analysis)

Find out **observable** variables outside of current functions:

- arguments;
- function return value;
- (mutable ) global variables;

Analyze their ranges and apply it in eventual solving.

## Taint Analysis

Is this bug related to **untrusted input**. For simplicity we assume the input of main function is **untrusted input**.
