# stdlib
import re
from typing import Optional
from typing import TYPE_CHECKING
import unittest

# pypi
from httpbin import app as httpbin_app
import pytest_httpbin.serve
import requests

# local
import metadata_parser

if TYPE_CHECKING:
    from requests import Response

# ==============================================================================


class SessionRedirect(requests.Session):
    num_checked = None

    def get_redirect_target(self, resp):
        # previous versions cached this for later use, but now we use a hook
        # cached_peername = metadata_parser.get_response_peername(resp)
        def _get():
            if self.num_checked is None:
                self.num_checked = 0
            self.num_checked += 1
            if resp.is_redirect:
                return resp.headers["location"]
            if resp.status_code == 200:
                # some servers will do a 200 but put a redirect header in there. WTF
                dumb_redirect = resp.headers.get("location")
                if dumb_redirect:
                    return dumb_redirect
            return None

        # --
        if not hasattr(resp, "_redirect_target"):
            resp._redirect_target = _get()
        return resp._redirect_target


class TestSessionsHttpBin(unittest.TestCase):

    func_hook_security_policy_url: Optional[metadata_parser.typing._Hook_SecurityPolicyUrl] = None

    def setUp(self):
        self.httpbin_server = pytest_httpbin.serve.Server(application=httpbin_app)
        self.httpbin_server.start()

    def tearDown(self):
        self.httpbin_server.stop()
        try:
            # we're not invoking `pytest_httpbin.serve.Server` in the standard way
            # our implementation was copied off another project
            # the `_server` is a wsgiref server, and in Py3 simply calling
            # `stop()` wil shutdown the server, but it will not `close()` any
            # lingering sockets. this explicitly does that.
            self.httpbin_server._server.socket.close()
        except Exception as exc:  # noqa: F841
            pass

    def test_no_session(self):
        """just checking for args"""
        url = self.httpbin_server.url + "/html"
        page = metadata_parser.MetadataParser(
            url=url, func_hook_security_policy_url=self.func_hook_security_policy_url
        )
        assert page
        assert page.url == url

    def test_simple_session(self):
        """just checking for args"""
        url = self.httpbin_server.url + "/html"
        with requests.Session() as s:
            page = metadata_parser.MetadataParser(
                url=url,
                requests_session=s,
                func_hook_security_policy_url=self.func_hook_security_policy_url,
            )
            assert page
            assert page.url == url

    def test_custom_session(self):
        """just checking for a custom session"""
        num_redirects = 4
        url = self.httpbin_server.url + "/redirect/%s" % num_redirects
        with SessionRedirect() as s:
            page: Optional[metadata_parser.MetadataParser]
            if self.func_hook_security_policy_url:
                with self.assertRaises(
                    metadata_parser.exceptions.SecurityPolicyViolation_URL_Redirect
                ) as cm:
                    page = metadata_parser.MetadataParser(
                        url=url,
                        requests_session=s,
                        func_hook_security_policy_url=self.func_hook_security_policy_url,
                    )
                page = cm.exception.metadataParser
            else:
                try:
                    page = metadata_parser.MetadataParser(
                        url=url,
                        requests_session=s,
                    )
                except metadata_parser.NotParsableJson as e:
                    page = e.metadataParser
            # typing scope
            assert page is not None
            # SecurityPolicyViolation_URL_Redirect is raised AFTER all requests are made
            # so this will be a `requests.Response` object in both scenarios above
            assert page.response is not None
            # we end on get
            self.assertEqual(page.response.url, self.httpbin_server.url + "/get")
            # the session should have checked the following responses: redirects + final
            self.assertEqual(num_redirects + 1, s.num_checked)
            self.assertEqual(num_redirects, len(page.response.history))

            # make sure that we tracked the peername.  httpbin will encode
            self.assertTrue(metadata_parser.get_response_peername(page.response))
            for h in page.response.history:
                self.assertTrue(metadata_parser.get_response_peername(h))


class TestSessionsHttpBin_HookFuncSecurityPolicy(TestSessionsHttpBin):

    def func_hook_security_policy_url(self, url: str, resp: Optional["Response"] = None):
        """
        Example security policy hook.
        
        The `/relative-redirect/2` url is tested by `[TestSessionsHttpBin].test_custom_session`
        
        The `/get` url is tested by `test_hook_security__initial_url`
        """
        if re.match(r"^http://127\.0\.0\.1:(?:\d+)/get$", url):
            return False
        if resp:
            for h in resp.history:
                if re.match(r"^http://127\.0\.0\.1:(?:\d+)/relative-redirect/2$", h.url):
                    return False
        return True


    def test_hook_security__initial_url(self):
        url = self.httpbin_server.url + "/get"
        with requests.Session() as s:
            with self.assertRaises(
                metadata_parser.exceptions.SecurityPolicyViolation_URL_Initial
            ) as cm:
                page = metadata_parser.MetadataParser(
                    url=url,
                    requests_session=s,
                    func_hook_security_policy_url=self.func_hook_security_policy_url,
                )
            page = cm.exception.metadataParser
            assert page is not None
            # SecurityPolicyViolation_URL_Initial is raised BEFORE any requests are made
            assert page.response is None

