CMAKE_MINIMUM_REQUIRED(VERSION 3.4)
PROJECT(llvm-pass-tutorial)

SET(CMAKE_CXX_STANDARD 11)

# wget https://github.com/llvm/llvm-project/releases/download/llvmorg-8.0.1/clang+llvm-8.0.1-powerpc64le-linux-ubuntu-16.04.tar.xz
FIND_PACKAGE(LLVM REQUIRED CONFIG HINTS "/home/ganler/Documents/CS526/clang+llvm-8.0.1-powerpc64le-linux-ubuntu-16.04/lib/cmake")

MESSAGE(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
MESSAGE(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

LIST(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")

INCLUDE(LLVM-Config)
INCLUDE(HandleLLVMOptions)
INCLUDE(AddLLVM)

INCLUDE_DIRECTORIES(${LLVM_INCLUDE_DIRS})

ADD_SUBDIRECTORY(SwapAdd)
ADD_SUBDIRECTORY(SROA)
