# stdlib
import unittest
from unittest.mock import Mock
from unittest.mock import patch

# pypi
import requests

# local
from metadata_parser import MetadataParser
from metadata_parser.exceptions import NotParsableFetchError


class TestSecurityHooks(unittest.TestCase):
    def test_request_failure_without_response_preserves_fetch_error(self):
        url = "https://example.com/"
        for error_type in (requests.ConnectionError, requests.Timeout):
            with self.subTest(error=error_type):
                hook = Mock(return_value=True)
                error = error_type("Request failed before receiving a response")
                page = MetadataParser(
                    url=url,
                    defer_fetch=True,
                    func_hook_security_policy_url=hook,
                )
                with patch.object(requests.Session, "get", side_effect=error):
                    with self.assertRaises(NotParsableFetchError) as caught:
                        page.fetch_url()
                self.assertIs(caught.exception.raised, error)
                self.assertIs(caught.exception.metadataParser, page)
                self.assertIsNone(page.response)
                # Only the initial URL check should run without a response.
                hook.assert_called_once_with(url)

    def test_http_error_response_still_reaches_policy_hook(self):
        url = "https://example.com/"
        hook = Mock(return_value=True)
        response = requests.Response()
        response.status_code = 404
        response.url = url
        page = MetadataParser(
            url=url,
            defer_fetch=True,
            func_hook_security_policy_url=hook,
        )
        with patch.object(requests.Session, "get", return_value=response):
            with self.assertRaises(NotParsableFetchError) as caught:
                page.fetch_url()
        self.assertIs(caught.exception.response, response)
        # Error responses are falsy, but must still be inspected by the hook.
        self.assertEqual(hook.call_count, 2)
        hook.assert_called_with(url, response)
