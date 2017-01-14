import metadata_parser
try:
    from urllib.parse import urlparse, urlencode
except ImportError:
    from urlparse import urlparse
    from urllib import urlencode

import unittest

if False:
    import logging
    l = logging.getLogger()
    l2 = logging.getLogger('metadata_parser')
    l.setLevel(logging.DEBUG)
    l2.setLevel(logging.DEBUG)

    ch = logging.StreamHandler()
    l.addHandler(ch)
    l2.addHandler(ch)


URLS_VALID = [
    'http://example.com',
    'http://example.com/',
    'http://example.com/one',
    'http://example.com/one/two.html',
    'http://foo.example.com',
    'http://example.com:80',
    'http://example.com:80/',
    'http://example.com:80/one',
    'http://example.com:80/one/two.html',
    'http://192.168.1.1',
    'http://192.168.1.1/',
    'http://192.168.1.1:80',
    'http://192.168.1.1:8080',
    'http://192.168.1.1:80/',
    'http://192.168.1.1:8080/',
    'http://192.168.1.1:80/a.html',
    'http://192.168.1.1:8080/a.html',

    'https://example.com',
    'https://example.com/',
    'https://example.com/one',
    'https://example.com/one/two.html',
    'https://foo.example.com',
    'https://example.com:80',
    'https://example.com:80/',
    'https://example.com:80/one',
    'https://example.com:80/one/two.html',
    'https://192.168.1.1',
    'https://192.168.1.1/',
    'https://192.168.1.1:80',
    'https://192.168.1.1:8080',
    'https://192.168.1.1:80/',
    'https://192.168.1.1:8080/',
    'https://192.168.1.1:80/a.html',
    'https://192.168.1.1:8080/a.html',
]

URLS_VALID_CONDITIONAL = [
    'http://localhost',
    'http://localhost:80',
    'http://localhost:8000',
    'http://localhost/foo',
    'http://localhost:80/foo',
    'http://localhost:8000/foo',
    'https://localhost',
    'https://localhost:80',
    'https://localhost:8000',
    'https://localhost/foo',
    'https://localhost:80/foo',
    'https://localhost:8000/foo',

    'http://127.0.0.1',
    'http://127.0.0.1:80',
    'http://127.0.0.1:8000',
    'http://127.0.0.1/foo',
    'http://127.0.0.1:80/foo',
    'http://127.0.0.1:8000/foo',
    'https://127.0.0.1',
    'https://127.0.0.1:80',
    'https://127.0.0.1:8000',
    'https://127.0.0.1/foo',
    'https://127.0.0.1:80/foo',
    'https://127.0.0.1:8000/foo',

    'http://0.0.0.0',
    'http://0.0.0.0:80',
    'http://0.0.0.0:8000',
    'http://0.0.0.0/foo',
    'http://0.0.0.0:80/foo',
    'http://0.0.0.0:8000/foo',
    'https://0.0.0.0',
    'https://0.0.0.0:80',
    'https://0.0.0.0:8000',
    'https://0.0.0.0/foo',
    'https://0.0.0.0:80/foo',
    'https://0.0.0.0:8000/foo',
]

URLS_INVALID = [
    'http://example_com',
    'http://example_com/',
    'http://example_com/one',
    'http://999.999.999.999/',
    'http://999.999.999.999.999/',
    'http://999.999.999.999.999:8080:8080',

    'https://example_com',
    'https://example_com/',
    'https://example_com/one',
    'https://999.999.999.999/',
    'https://999.999.999.999.999/',
    'https://999.999.999.999.999:8080:8080',
]


class TestUrlParsing(unittest.TestCase):
    """
    python -m unittest tests.url_parsing.TestUrls
    
    Ensures URLs are parsed correctly as valid/invalid
    """
    def test_urls_valid(self):
        for i in URLS_VALID:
            parsed = urlparse(i)
            self.assertTrue(metadata_parser.is_parsed_valid_url(parsed))

    def test_urls_invalid(self):
        for i in URLS_INVALID:
            parsed = urlparse(i)
            self.assertFalse(metadata_parser.is_parsed_valid_url(parsed))

    def test_urls_valid_conditional(self):
        for i in URLS_VALID_CONDITIONAL:
            parsed = urlparse(i)
            self.assertFalse(metadata_parser.is_parsed_valid_url(parsed, require_public_netloc=True, allow_localhosts=False))
            self.assertTrue(metadata_parser.is_parsed_valid_url(parsed, require_public_netloc=False, allow_localhosts=True))

