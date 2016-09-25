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

        print cache.metadata
        cache.clear()

    def test_etagmatch(self):
        cache = ResourceCache(directory='/tmp')
        cache.clear()

        entry = cache.get('http://downloads.anchore.s3-website-us-west-2.amazonaws.com/')
        print entry
        assert entry['content'] is not None
        cache.clear()

