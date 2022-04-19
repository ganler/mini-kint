import os
import unittest
from aem import con
import llvmlite.binding as llvm
import re

# All these initializations are required for code generation!
llvm.initialize()
llvm.initialize_native_target()
llvm.initialize_native_asmprinter()  # yes, even this one

MKINT_IR_TAINT = "mkint.taint"
MKINT_IR_SINK = "mkint.sink"
MKINT_IR_ERR = "mkint.err"

int_err_type_map = {}
# OUT_OF_BOUND - 0
int_err_type_map[0] = "OUT_OF_BOUND"
# DIV_BY_ZERO - 1
int_err_type_map[1] = "DIV_BY_ZERO"
# BAD_SHIFT - 2
int_err_type_map[2] = "BAD_SHIFT"
# NEG_IDX - 3
int_err_type_map[3] = "NEG_IDX"
# VIOLATE_ANN - 4
int_err_type_map[4] = "VIOLATE_ANN"

before_annot_map = {}
before_annot_map['int_overflow'] = 0
before_annot_map['int_overflow_ub'] = 0
before_annot_map['div_by_zero'] = 1
before_annot_map['bad_shift'] = 2
before_annot_map['array_index'] = 3


class TestMKint(unittest.TestCase):
    AFTER_FILE=os.environ['AFTER']
    AFTER_IR=open(AFTER_FILE).read()

    BEFORE_FILE=os.environ['BEFORE']
    BEFORE_IR=open(BEFORE_FILE).read()

    def test_IR_correct(self):
        m = llvm.parse_assembly(TestMKint.BEFORE_IR)
        m.verify()

        m = llvm.parse_assembly(TestMKint.AFTER_IR)
        m.verify()

    def test_i_annoted(self):
        m = llvm.parse_assembly(TestMKint.BEFORE_IR)
        err_to_find = {}
        for f in m.functions:
            for b in f.blocks:
                for i in b.instructions:
                    # print(f'Instruction: {i.name}/`{i.opcode}`/`{i.type}`: `{i}`')
                    assert i.is_instruction and not (i.is_function or i.is_block)

                    err = re.findall("![a-zA-Z_]+", i.__str__())
                    if len(err) != 1:
                        continue

                    err = err[0][1:]
                    # print(f'==== {err}')
                    if err in before_annot_map:
                        err_to_find[f'Instruction: {i.name}/`{i.opcode}`/`{i.type}`'] = before_annot_map[err]

        m = llvm.parse_assembly(TestMKint.AFTER_IR)
        for f in m.functions:
            # print(f'Function: {f.name}/`{f.type}`')

            assert f.module is m
            assert f.function is None
            assert f.block is None
            assert f.is_function and not (f.is_block or f.is_instruction)
            # print(f'Function attributes: {list(f.attributes)}')
            # for a in f.arguments:
            #     print(f'Argument: {a.name}/`{a.type}`')
            #     print(f'Argument attributes: {list(a.attributes)}')
            for b in f.blocks:
                # print(f'Block: {b.name}/`{b.type}`\n{b}\nEnd of Block')
                assert b.module is m
                assert b.function is f
                assert b.block is None
                assert b.is_block and not (b.is_function or b.is_instruction)
                for i in b.instructions:
                    print(f'Instruction: {i.name}/`{i.opcode}`/`{i.type}`: `{i}`')
                    # print(f'Attributes: {list(i.attributes)}')

                    assert i.is_instruction and not (i.is_function or i.is_block)

                    err = re.findall("![a-zA-Z]+", i.__str__())
                    if len(err) != 1:
                        continue

                    err = err[0][1:]

                    err_type = re.findall("![0-9]+", i.__str__())
                    if len(err_type) != 1:
                        continue

                    err_type = err_type[0][1:]
                    if 'mkint' not in err:
                        continue
                    print(f'Error: {err}, Error type: {err_type}')

                    instruction = f'Instruction: {i.name}/`{i.opcode}`/`{i.type}`'
                    assert instruction in err_to_find

                    # for o in i.operands:
                    #     print(f'Operand: {o.name}/{o.type}')
    

if __name__ == '__main__':
    print("Usage: BEFORE=<before.ll> AFTER=<after.ll> python3 llvm_lite.py")
    unittest.main()
