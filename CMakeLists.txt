CMAKE_MINIMUM_REQUIRED(VERSION 3.4)
PROJECT(llvm-pass-tutorial)

SET(CMAKE_CXX_STANDARD 11)
SET(LLVM_ROOT CACHE STRING "")

IF (LLVM_ROOT)
    # wget https://github.com/llvm/llvm-project/releases/download/llvmorg-8.0.1/clang+llvm-8.0.1-powerpc64le-linux-ubuntu-16.04.tar.xz
    MESSAGE(STATUS "Searching LLVM_ROOT=${LLVM_ROOT}")
    FIND_PACKAGE(LLVM REQUIRED CONFIG HINTS "${LLVM_ROOT}")
ELSE()
    MESSAGE(FATAL_ERROR "Please set `LLVM_ROOT` to the prefix path. You can use `llvm-config --prefix` to get your default LLVM_ROOT.")
ENDIF()

MESSAGE(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
MESSAGE(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

LIST(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")

INCLUDE(LLVM-Config)
INCLUDE(HandleLLVMOptions)
INCLUDE(AddLLVM)

INCLUDE_DIRECTORIES(${LLVM_INCLUDE_DIRS})

ADD_SUBDIRECTORY(tests)
ADD_SUBDIRECTORY(SwapAdd)
ADD_SUBDIRECTORY(SROA)
