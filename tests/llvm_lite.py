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
    "int_overflow": "integer overflow",
    "int_overflow_ub": "integer overflow",
    "array_index": "array index out of bound",
    "bad_shift": "bad shift",
    "cmp_true": "impossible false branch",
    "cmp_false": "impossible true branch",
    "div_by_zero": "divide by zero" 
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
        print(f'== {TestMKint.AFTER_FILE}')
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

        names = TestMKint.AFTER_FILE.split("/")[-1].split("-")
        ERR_NAME = names[0]
        ERR_FN_NAME = names[2].split(".")[0]

        meta_map = {}
        for id, line in enumerate(TestMKint.AFTER_IR.split('\n')):
            meta = re.findall("^![0-9.]+", line)
            if len(meta) == 1:
                v = line.split(' = ')[1]
                if '"' not in v:
                    continue
                v = v.split('"')[1]
                meta_map[meta[0]] = v

        ERR = None
        ERR_FN = None
        m = llvm.parse_assembly(TestMKint.AFTER_IR)

        # print(f"+++++ m: {m}")

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
                    # print(f'Attributes: {list(i.attributes)}')

                    assert i.is_instruction and not (i.is_function or i.is_block)

                    err = re.findall("!mkint.err", i.__str__())
                    if len(err) != 1:
                        continue

                    mkinterr = re.findall("!mkint.err ![0-9]+", f.__str__())[0]
                    err_type = mkinterr.split(" ")[1]

                    ERR_FN = f.name
                    ERR = meta_map[err_type]

                    print(f'== Instruction: {i.name}/`{i.opcode}`/`{i.type}`: `{i}`')
                    print(f'== Error: {err}, Error type: {meta_map[err_type]}, ERR_FN: {ERR_FN}')

                    # instruction = f'Instruction: {i.name}/`{i.opcode}`/`{i.type}`'
                    # assert instruction in err_to_find

                    # assert err_type
                    

                    # for o in i.operands:
                    #     print(f'Operand: {o.name}/{o.type}')

        print(f'== ERR: {ERR}, ERR_FN: {ERR_FN}')

        if ERR_FN_NAME == "none":
            assert ERR == None
            assert ERR_FN == None
        else:
            assert ERR_NAME_MAP[ERR_NAME] == ERR
            assert ERR_FN_NAME == ERR_FN

if __name__ == '__main__':
    print("Usage: BEFORE=<before.ll> AFTER=<after.ll> python3 llvm_lite.py")
    unittest.main()
