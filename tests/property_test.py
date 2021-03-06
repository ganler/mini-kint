import os
import unittest
import parser

class TestMKint(unittest.TestCase):
    BEFORE_FILE=os.environ['BEFORE']
    AFTER_FILE=os.environ['AFTER']
    BEFORE_IR=open(BEFORE_FILE).read()
    AFTER_IR=open(AFTER_FILE).read()

    def test_no_struct(self):
        for id, line in enumerate(TestMKint.AFTER_IR.split('\n')):
            r = parser.PARSER.parse_string(line)
            print(r.pprint())

if __name__ == '__main__':
    print("Usage: BEFORE=<before.ll> AFTER=<after.ll> python3 property_test.py")
    unittest.main()
