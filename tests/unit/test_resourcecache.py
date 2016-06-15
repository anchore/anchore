import unittest
import logging
import os

from anchore.util.resources import ResourceCache

logging.basicConfig(level='DEBUG')


class TestResourceCache (unittest.TestCase):
    def test_basic(self):
        cache = ResourceCache(directory='/tmp')
        cache.clear()
        assert cache.is_empty()

        entry = cache.get('http://downloads.anchore.s3-website-us-west-2.amazonaws.com/')
        print entry
        assert entry['content'] is not None

        entry = cache.get('s3://downloads.anchore/readme.txt')
        print entry
        assert entry['content'] is not None

        entry = cache.get('s3://anchore-sync-service/subscriptions/engine.json')
        print entry
        assert entry['content'] is not None

        print cache.metadata
        cache.clear()

    def test_etagmatch(self):
        cache = ResourceCache(directory='/tmp')
        cache.clear()

        entry = cache.get('s3://downloads.anchore/readme.txt')
        print entry
        assert entry['content'] is not None

        entry = cache.get('s3://downloads.anchore/readme.txt')
        print entry
        assert entry['content'] is not None
        cache.clear()

    def test_upload(self):
        cache = ResourceCache(directory='/tmp')
        cache.clear()

        print 'Testing GET'
        entry = cache.get('s3://anchore-testing/testkey1')
        print entry
        assert entry['content'] is not None

        if not os.path.exists('./testfile'):
            with open('./testfile', 'w') as f:
                f.write('Some content here')

        print 'Testing PUT 1'
        entry = cache.upload('./testfile', 's3://anchore-testing/testkey')
        print entry
        assert entry['content'] is not None
        date1 = entry['last-modified']

        print 'Testing PUT of existing file'
        entry = cache.upload('./testfile', 's3://anchore-testing/testkey')
        print entry
        assert entry['content'] is not None
        assert date1 == entry['last-modified']

        cache.clear()








