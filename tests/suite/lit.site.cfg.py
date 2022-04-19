import sys

config.llvm_tools_dir = "/bin"
config.llvm_shlib_ext = ".dylib"
config.llvm_build_dir = "/Users/likun/Projects/course/CS526/mini-kint/tests/suite"

import lit.llvm

lit.llvm.initialize(lit_config, config)

config.test_exec_root = os.path.join("/Users/likun/Projects/course/CS526/mini-kint/tests/suite")

lit_config.load_config(config, "/Users/likun/Projects/course/CS526/mini-kint/tests/lit.cfg.py")
