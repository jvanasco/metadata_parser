import metadata_parser
try:
    from urllib.parse import urlparse, urlencode
except ImportError:
    from urlparse import urlparse
    from urllib import urlencode

import unittest


class TestIpLookups(unittest.TestCase):
    """
    """
    def test_ip_lookup(self):
        url = "http://example.com/"
        page = metadata_parser.MetadataParser(url=url)
        self.assertTrue(page.peername)


