# stdlib
import unittest

# local
import metadata_parser

# ==============================================================================


class TestIpLookups(unittest.TestCase):
    """"""

    def test_ip_lookup(self):
        """
        this is using the live internet

        todo: use httpbin
        """
        url = "https://example.com/"
        page = metadata_parser.MetadataParser(url=url)
        self.assertTrue(page.peername)
