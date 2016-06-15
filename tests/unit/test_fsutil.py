import unittest
from anchore.util.fs_util import calc_file_md5


class TestFSUtil (unittest.TestCase):
    def test_calc_md5(self):
        print 'Starting md5 test'
        testfile = './testfile'

        with open(testfile, 'w') as f:
            f.write('Some boring content here...blah blah blah')

        print 'MD5 = %s' % calc_file_md5(testfile, chunk_size=10)

