# stdlib
import unittest

# local
import metadata_parser

# ==============================================================================


class TestIpLookups(unittest.TestCase):
    """"""

    def test_ip_lookup(self):
        url = "http://example.com/"
        page = metadata_parser.MetadataParser(url=url)
        self.assertTrue(page.peername)
