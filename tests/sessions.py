import metadata_parser
import unittest
import requests

from httpbin import app as httpbin_app
import pytest_httpbin.serve


class SessionRedirect(requests.Session):
    num_checked = None

    def get_redirect_target(self, resp):
        # cache this for later use
        cached_peername = metadata_parser.get_response_peername(resp)
        if self.num_checked is None:
            self.num_checked = 0
        self.num_checked += 1
        if resp.is_redirect:
            return resp.headers['location']
        if resp.status_code == 200:
            # some servers will do a 200 but put a redirect header in there. WTF
            dumb_redirect = resp.headers.get('location')
            if dumb_redirect:
                return dumb_redirect
        return None


class TestSessionsHttpBin(unittest.TestCase):

    def setUp(self):
        server = pytest_httpbin.serve.Server(application=httpbin_app)
        server.start()
        self.httpbin_server = server
    
    def tearDown(self):
        self.httpbin_server.stop()

    def test_no_session(self):
        '''just checking for args'''
        url = self.httpbin_server.url + '/html'
        page = metadata_parser.MetadataParser(url=url)
        assert page
        assert page.url == url

    def test_simple_session(self):
        '''just checking for args'''
        url = self.httpbin_server.url + '/html'
        s = requests.Session()
        page = metadata_parser.MetadataParser(url=url, requests_session=s)
        assert page
        assert page.url == url

    def test_custom_session(self):
        '''just checking for a custom session'''
        num_redirects = 4
        url = self.httpbin_server.url + '/redirect/%s' % num_redirects
        s = SessionRedirect()
        try:
            page = metadata_parser.MetadataParser(url=url, requests_session=s)
        except metadata_parser.NotParsableJson as e:
            page = e.metadataParser
        # we end on get
        self.assertEqual(page.response.url, self.httpbin_server.url + '/get')
        # the session should have checked the following responses: redirects + final
        self.assertEqual(num_redirects + 1, s.num_checked)
        self.assertEqual(num_redirects, len(page.response.history))
        
        # make sure that we tracked the peername.  httpbin will encode
        self.assertTrue(metadata_parser.get_response_peername(page.response))
        for h in page.response.history:
            self.assertTrue(metadata_parser.get_response_peername(h))
            
    
