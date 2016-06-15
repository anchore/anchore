import unittest
from anchore.util.scripting import ScriptSetExecutor


class TestScriptModule (unittest.TestCase):

    def runTest(self):
        s = ScriptSetExecutor('data/scripts')
        assert s.check()
        print s.get_scripts()
        assert s.get_scripts() == ['01_test.sh','02_test.sh', '03_test_fail.sh', '04_test.sh']
        output = s.execute(capture_output=True, fail_fast=False)
        print output
        assert output == {
            'data/scripts/01_test.sh': [0, 'test1\n'],
            'data/scripts/02_test.sh': [0, 'test2\n'],
            'data/scripts/03_test_fail.sh': [2, 'Testing to fail\n'],
            'data/scripts/04_test.sh': [0, 'test4\n']
        }

        output = s.execute(capture_output=True, fail_fast=True)
        print output
        assert output == {
            'data/scripts/01_test.sh': [0, 'test1\n'],
            'data/scripts/02_test.sh': [0, 'test2\n'],
            'data/scripts/03_test_fail.sh': [2, 'Testing to fail\n']
        }

