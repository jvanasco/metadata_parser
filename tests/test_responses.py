# -*- coding: utf-8 -*-

# stdlib
import unittest

# pypi
import requests
import responses

# local
from metadata_parser import derive_encoding__hook

# ==============================================================================


URLS_HEADER = {
    "https://example.com/header=none": (None, "ISO-8859-1", "&hearts;"),
    "https://example.com/header=ISO-8859-1": ("ISO-8859-1", "ISO-8859-1", "&hearts;"),
    "https://example.com/header=utf-8": ("utf-8", "utf-8", "♥"),
    "https://example.com/header=UTF-8": ("UTF-8", "UTF-8", "♥"),
}
URLS_META = {
    "https://example.com/content_type=none": (None, "ISO-8859-1", "&hearts;"),
    "https://example.com/content_type=ISO-8859-1": (
        "ISO-8859-1",
        "ISO-8859-1",
        "&hearts;",
    ),
    "https://example.com/content_type=utf-8": ("utf-8", "utf-8", "♥"),
    "https://example.com/content_type=UTF-8": ("UTF-8", "UTF-8", "♥"),
}


class TestMockedResponse(unittest.TestCase):
    def test_simple_encoding_found(self):
        """these tests just check to see we derive the right content with `derive_encoding__hook`"""

        requests_session = requests.Session()
        requests_session.hooks["response"].append(derive_encoding__hook)

        with responses.RequestsMock(assert_all_requests_are_fired=False) as rsps:
            # track results to this
            to_test = {}

            # set up the header tests
            for url in URLS_HEADER.keys():
                (_header, _expected, _body_char) = URLS_HEADER[url]
                _content_type = "text/html"
                if _header:
                    _content_type = "text/html; charset=%s" % _header
                _body = "<html><head></head><body>%s</body></html>" % _body_char
                rsps.add(
                    responses.GET,
                    url,
                    body=_body,
                    status=200,
                    content_type=_content_type,
                )
                to_test[url] = (_expected, _body)

            # set up the meta tests
            for url in URLS_META.keys():
                (_header, _expected, _body_char) = URLS_META[url]
                _body = "<html><head></head><body>%s</body></html>" % _body_char
                if _header:
                    _body = (
                        '<html><head><meta charset="%s"></head><body>%s</body></html>'
                        % (_header, _body_char)
                    )
                rsps.add(
                    responses.GET, url, body=_body, status=200, content_type="text/html"
                )
                to_test[url] = (_expected, _body)

            for url in to_test:
                (_expected, _body) = to_test[url]
                r = requests_session.get(url)
                self.assertEqual(r.status_code, 200)
                self.assertEqual(r.encoding, _expected)
                self.assertEqual(r.text, _body)
