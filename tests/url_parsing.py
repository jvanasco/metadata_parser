import metadata_parser
import urlparse

import unittest


URLS_GOOD = [
    'http://example.com',
    'http://example.com/',
    'http://example.com/one',
    'http://example.com/one/two.html',
    'http://foo.example.com',
    'http://localhost',
    'http://192.168.1.1',
    'http://192.168.1.1/',
]

URLS_BAD = [
    'http://example_com',
    'http://example_com/',
    'http://example_com/one',
    'http://999.999.999.999/',
    'http://999.999.999.999.999/',
]


class TestUrls(unittest.TestCase):

    def test_urls_good(self):
        for i in URLS_GOOD:
            parsed = urlparse.urlparse(i)
            self.assertTrue(metadata_parser.is_parsed_valid_url(parsed))

    def test_urls_bad(self):
        for i in URLS_BAD:
            parsed = urlparse.urlparse(i)
            self.assertFalse(metadata_parser.is_parsed_valid_url(parsed))
