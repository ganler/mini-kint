include(ExternalProject)
EXTERNALPROJECT_ADD(
  z3-repo

  GIT_REPOSITORY "https://github.com/Z3Prover/z3.git"
  GIT_TAG "z3-4.8.15"
  
  UPDATE_COMMAND ""
  PATCH_COMMAND ""
  
  CMAKE_ARGS 
    -DZ3_ENABLE_EXAMPLE_TARGETS=0
    -DZ3_BUILD_PYTHON_BINDINGS=0
    -DZ3_BUILD_TEST_EXECUTABLES=0
    -DZ3_BUILD_EXECUTABLE=0
    -DCMAKE_INSTALL_PREFIX=${CMAKE_CURRENT_BINARY_DIR}/z3
  
  TEST_COMMAND ""
)

INCLUDE_DIRECTORIES(${CMAKE_CURRENT_BINARY_DIR}/z3/include)

# https://github.com/llvm-mirror/llvm/blob/master/cmake/modules/AddLLVM.cmake
add_llvm_library(MiniKintPass 
    MODULE mkint.cpp log.cpp
    DEPENDS z3-repo
    LINK_LIBS z3
    PLUGIN_TOOL opt
    )
