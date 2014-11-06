import metadata_parser
import urlparse

import unittest

if False:
    import logging
    l = logging.getLogger()
    l2 = logging.getLogger('metdata_parser')
    l.setLevel(logging.DEBUG)
    l2.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    l.addHandler(ch)
    l2.addHandler(ch)


URLS_GOOD = [
    'http://example.com',
    'http://example.com/',
    'http://example.com/one',
    'http://example.com/one/two.html',
    'http://foo.example.com',
    'http://localhost',
    'http://192.168.1.1',
    'http://192.168.1.1/',
    'http://192.168.1.1:80',
    'http://192.168.1.1:8080',
    'http://192.168.1.1:80/',
    'http://192.168.1.1:8080/',
    'http://192.168.1.1:80/a.html',
    'http://192.168.1.1:8080/a.html',
    'http://example.com:80',
    'http://example.com:80/',
    'http://example.com:80/one',
    'http://example.com:80/one/two.html',
]

URLS_BAD = [
    'http://example_com',
    'http://example_com/',
    'http://example_com/one',
    'http://999.999.999.999/',
    'http://999.999.999.999.999/',
    'http://999.999.999.999.999:8080:8080',
]


class TestUrls(unittest.TestCase):
    """
        python -m unittest tests.url_parsing.TestUrls
    """
    def test_urls_good(self):
        for i in URLS_GOOD:
            parsed = urlparse.urlparse(i)
            self.assertTrue(metadata_parser.is_parsed_valid_url(parsed))

    def test_urls_bad(self):
        for i in URLS_BAD:
            parsed = urlparse.urlparse(i)
            self.assertFalse(metadata_parser.is_parsed_valid_url(parsed))
