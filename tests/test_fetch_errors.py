# stdlib
from unittest.mock import patch

# pypi
import pytest
import requests

# local
from metadata_parser import MetadataParser
from metadata_parser.exceptions import NotParsable
from metadata_parser.exceptions import NotParsableFetchError
from metadata_parser.exceptions import NotParsableRedirect
from metadata_parser.exceptions import RedirectDetected

URL = "https://example.com/index.html"
HTML = "<html><head><title>Fetched</title></head></html>"


def make_response(status=200, content_type="text/html"):
    response = requests.Response()
    response.url = URL
    response.status_code = status
    response.encoding = "utf-8"
    response._content = HTML.encode()
    if content_type:
        response.headers["Content-Type"] = content_type
    return response


def test_deferred_fetch_parses_only_when_invoked():
    with patch.object(requests.Session, "get", return_value=make_response()) as get:
        page = MetadataParser(url=URL, defer_fetch=True)
        get.assert_not_called()
        assert page.parsed_result.soup is None
        page.deferred_fetch()
    assert page.parsed_result.select_first_match("title") == "Fetched"
    assert page.parsed_result.response_history.history == [(200, URL)]


def test_deferred_fetch_requires_configuration():
    with pytest.raises(ValueError, match="no `deferred_fetch` set"):
        MetadataParser().deferred_fetch()


@pytest.mark.parametrize(
    "path,allowed",
    (
        ("/index.html", True),
        ("/article", True),
        ("/", True),
        ("/photo.jpg", False),
    ),
)
def test_extension_filter_runs_before_fetch(path, allowed):
    with patch.object(requests.Session, "get", return_value=make_response()) as get:
        if allowed:
            MetadataParser(
                url="https://example.com" + path, only_parse_file_extensions=["html"]
            )
            get.assert_called_once()
        else:
            with pytest.raises(NotParsable, match="I don't know what this file is"):
                MetadataParser(
                    url="https://example.com" + path,
                    only_parse_file_extensions=["html"],
                )
            get.assert_not_called()


@pytest.mark.parametrize("status", (301, 302, 307, 308))
@pytest.mark.parametrize("location", ("/destination", None))
def test_disabled_redirects_expose_redirect_details(status, location):
    response = make_response(status)
    if location:
        response.headers["Location"] = location
    error_type = RedirectDetected if location else NotParsableRedirect
    with patch.object(requests.Session, "get", return_value=response):
        with pytest.raises(error_type) as caught:
            MetadataParser(url=URL, allow_redirects=False)
    assert caught.value.code == status
    assert caught.value.metadataParser.response is response
    if location:
        assert caught.value.location == location
        assert caught.value.response is response


@pytest.mark.parametrize("headers,retry", (({}, True), ({"User-Agent": "test"}, False)))
def test_dropped_request_is_not_retried_without_opt_in(headers, retry):
    error = requests.exceptions.ChunkedEncodingError("Dropped")
    with patch.object(requests.Session, "get", side_effect=error) as get:
        with pytest.raises(NotParsableFetchError) as caught:
            MetadataParser(
                url=URL, url_headers=headers, retry_dropped_without_headers=retry
            )
    get.assert_called_once()
    assert caught.value.raised is error


def test_opted_in_dropped_request_retries_without_custom_headers():
    error = requests.exceptions.ChunkedEncodingError("Dropped")
    with patch.object(
        requests.Session, "get", side_effect=[error, make_response()]
    ) as get:
        page = MetadataParser(
            url=URL,
            url_headers={"User-Agent": "test"},
            retry_dropped_without_headers=True,
        )
    assert get.call_count == 2
    assert get.call_args_list[0][1]["headers"] == {"User-Agent": "test"}
    assert get.call_args_list[1][1]["headers"] == {}
    assert page.parsed_result.select_first_match("title") == "Fetched"


@pytest.mark.parametrize("content_type", (None, "image/png"))
def test_unknown_content_type_requires_explicit_override(content_type):
    with patch.object(
        requests.Session, "get", return_value=make_response(content_type=content_type)
    ):
        with pytest.raises(NotParsable, match="I don't know how to parse"):
            MetadataParser(url=URL)
        page = MetadataParser(url=URL, force_parse_invalid_content_type=True)
    assert page.parsed_result.select_first_match("title") == "Fetched"


def test_request_exception_keeps_attached_response_and_redirect_history():
    response = make_response(502)
    response.history = [make_response(302)]
    error = requests.ConnectionError("Disconnected", response=response)
    with patch.object(requests.Session, "get", side_effect=error):
        with pytest.raises(NotParsableFetchError) as caught:
            MetadataParser(url=URL)
    assert caught.value.raised is error
    assert caught.value.metadataParser.response is response
    assert caught.value.metadataParser.is_redirect is True
