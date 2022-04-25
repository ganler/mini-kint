import os
import unittest
import llvmlite.binding as llvm
import re
import parser

# All these initializations are required for code generation!
llvm.initialize()
llvm.initialize_native_target()
llvm.initialize_native_asmprinter()  # yes, even this one

ERR_NAME_MAP = {
    "int_overflow": "integer overflow"
}

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
        # m = llvm.parse_assembly(TestMKint.BEFORE_IR)
        # err_to_find = {}
        # for f in m.functions:
        #     for b in f.blocks:
        #         for i in b.instructions:
        #             # print(f'Instruction: {i.name}/`{i.opcode}`/`{i.type}`: `{i}`')
        #             assert i.is_instruction and not (i.is_function or i.is_block)

        #             err = re.findall("![a-zA-Z_]+", i.__str__())
        #             if len(err) != 1:
        #                 continue

        #             err = err[0][1:]
        #             # print(f'==== {err}')
        #             if err in before_annot_map:
        #                 err_to_find[f'Instruction: {i.name}/`{i.opcode}`/`{i.type}`'] = before_annot_map[err]

        names = TestMKint.AFTER_FILE.split("-")
        ERR_NAME = names[0]
        ERR_FN_NAME = names[2].split(".")[0]

        meta_map = {}
        for id, line in enumerate(TestMKint.AFTER_IR.split('\n')):
            meta = re.findall("^![0-9.]+", line)
            if len(meta) == 1:
                v = line.split(' = ')[1]
                v = v.split('"')[1]
                meta_map[meta[0]] = v

        ERR = None
        ERR_FN = None
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

                    err = re.findall("![a-zA-Z.]+", i.__str__())
                    if len(err) != 1:
                        continue

                    err = err[0]

                    err_type = re.findall("![0-9]+", i.__str__())
                    if len(err_type) != 1:
                        continue

                    if 'mkint.err' not in err:
                        continue

                    mkinterr = re.findall("!mkint.err ![0-9]+", f.__str__())[0]
                    err_type = mkinterr.split(" ")[1]

                    print(f'Error: {err}, Error type: {meta_map[err_type]}')
                    ERR_FN = f.name
                    ERR = meta_map[err_type]

                    # instruction = f'Instruction: {i.name}/`{i.opcode}`/`{i.type}`'
                    # assert instruction in err_to_find

                    # assert err_type
                    

                    # for o in i.operands:
                    #     print(f'Operand: {o.name}/{o.type}')

        assert ERR_NAME_MAP[ERR_NAME] == ERR
        assert ERR_FN_NAME == ERR_FN

if __name__ == '__main__':
    print("Usage: BEFORE=<before.ll> AFTER=<after.ll> python3 llvm_lite.py")
    unittest.main()
