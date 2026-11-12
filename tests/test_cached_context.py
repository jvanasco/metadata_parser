# stdlib
from unittest.mock import patch

# pypi
import pytest
import requests

# local
import metadata_parser
from metadata_parser import MetadataParser


REQUESTED_URL = "http://example.com/start"
RESPONSE_URL = "https://example.com/articles/page.html"
HTML = '<html><head><link rel="canonical" href="next.html"></head></html>'


@pytest.fixture(autouse=True)
def offline_domains(monkeypatch):
    if metadata_parser.USE_TLDEXTRACT:
        extract = metadata_parser.tldextract.TLDExtract(
            suffix_list_urls=(), cache_dir=None
        )
        monkeypatch.setattr(metadata_parser.tldextract, "extract", extract)


@pytest.mark.parametrize("html", (HTML, ""))
def test_cached_html_restores_both_urls_without_fetching(html):
    with patch.object(requests.Session, "get") as fetch:
        page = MetadataParser(
            url=REQUESTED_URL, url_actual=RESPONSE_URL, html=html
        )
    fetch.assert_not_called()
    assert page.url == REQUESTED_URL
    assert page.url_actual == RESPONSE_URL
    assert page.response.url == RESPONSE_URL
    internal = page.parsed_result.metadata["_internal"]
    assert internal["url"] == REQUESTED_URL
    assert internal["url_actual"] == RESPONSE_URL
    assert page.get_url_scheme() == "https"
    assert page.absolute_url("next.html") == "https://example.com/articles/next.html"
    if html:
        assert page.get_url_canonical() == "https://example.com/articles/next.html"


def test_cached_html_defaults_actual_url_to_requested_url():
    page = MetadataParser(url=REQUESTED_URL, html=HTML)
    assert page.url_actual == REQUESTED_URL
    assert page.response.url == REQUESTED_URL
    assert page.parsed_result.metadata["_internal"]["url_actual"] == REQUESTED_URL


def test_cached_actual_url_requires_html_before_fetching():
    with patch.object(requests.Session, "get") as fetch:
        with pytest.raises(ValueError, match="`url_actual` requires cached `html`"):
            MetadataParser(url=REQUESTED_URL, url_actual=RESPONSE_URL)
    fetch.assert_not_called()


def test_live_fetch_records_response_url_and_preserves_requested_url():
    response = requests.Response()
    response.url = RESPONSE_URL
    response.status_code = 200
    response.headers["content-type"] = "text/html; charset=utf-8"
    response.encoding = "utf-8"
    response._content = HTML.encode("utf-8")
    with patch.object(requests.Session, "get", return_value=response) as fetch:
        page = MetadataParser(url=REQUESTED_URL)
    assert fetch.call_args[0] == (REQUESTED_URL,)
    assert page.url == REQUESTED_URL
    assert page.url_actual == RESPONSE_URL
    internal = page.parsed_result.metadata["_internal"]
    assert internal["url"] == REQUESTED_URL
    assert internal["url_actual"] == RESPONSE_URL
