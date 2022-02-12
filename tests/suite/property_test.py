import os
import unittest

class TestSORA(unittest.TestCase):
    BEFORE_FILE=os.environ['BEFORE']
    AFTER_FILE=os.environ['AFTER']
    BEFORE_IR=open(BEFORE_FILE).read()
    AFTER_IR=open(AFTER_FILE).read()

    def test_no_struct(self):
        for id, line in enumerate(TestSORA.AFTER_IR.split('\n')):
            self.assertFalse(
                r'alloca %struct.' in line, "struct alloca found after SORA in {}:{}".format(TestSORA.AFTER_FILE, id + 1))

if __name__ == '__main__':
    print("Usage: BEFORE=<before.ll> AFTER=<after.ll> python3 property_test.py")
    unittest.main()
