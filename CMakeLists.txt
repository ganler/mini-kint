CMAKE_MINIMUM_REQUIRED(VERSION 3.4)
PROJECT(llvm-pass-tutorial)

SET(CMAKE_CXX_STANDARD 17)
SET(LLVM_ROOT "" CACHE STRING "Path to LLVM-8.0.1's ROOT directory (contains bin, lib, etc.)")

IF (LLVM_ROOT)
    # Use LLVM-8 for project 1.
    # wget https://github.com/llvm/llvm-project/releases/download/llvmorg-8.0.1/clang+llvm-8.0.1-powerpc64le-linux-ubuntu-16.04.tar.xz
    MESSAGE(STATUS "Searching LLVM_ROOT=${LLVM_ROOT}")
    FIND_PACKAGE(LLVM REQUIRED CONFIG HINTS "${LLVM_ROOT}")
ELSE()
    FIND_PACKAGE(LLVM REQUIRED CONFIG)
ENDIF()

MESSAGE(STATUS "Found LLVM ${LLVM_PACKAGE_VERSION}")
MESSAGE(STATUS "Using LLVMConfig.cmake in: ${LLVM_DIR}")

LIST(APPEND CMAKE_MODULE_PATH "${LLVM_CMAKE_DIR}")

INCLUDE(AddLLVM)

ADD_DEFINITIONS(${LLVM_DEFINITIONS})
INCLUDE_DIRECTORIES(${LLVM_INCLUDE_DIRS})

ADD_SUBDIRECTORY(tests)
# ADD_SUBDIRECTORY(sora) # For project 1
ADD_SUBDIRECTORY(mkint) # For project 2
