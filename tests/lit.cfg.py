import platform
import os

import lit.formats
from lit.llvm import llvm_config
from lit.llvm.subst import ToolSubst

config.name = 'lit-SROA-jiawei6'
config.test_format = lit.formats.ShTest(True)
config.suffixes = ['.c']
config.test_source_root = os.path.dirname(__file__)
