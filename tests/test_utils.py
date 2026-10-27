# stdlib
import datetime
from unittest.mock import Mock
from urllib.parse import urlparse

# pypi
import pytest
from requests.structures import CaseInsensitiveDict

# local
from metadata_parser import config
from metadata_parser import utils


@pytest.mark.parametrize("encoder", (utils.decode_html, utils.encode_ascii))
def test_dublin_core_encoder_extracts_content(encoder):
    assert encoder({"content": "Café"}, "dc") == "Cafe"
    assert encoder({}, "dc") == ""
    with pytest.raises(ValueError):
        encoder({"content": "Title"}, "meta")


def test_decode_html_unescapes_entities_and_normalizes_unicode():
    assert utils.decode_html("Caf&eacute; &amp; tea") == "Cafe & tea"
    assert utils.encode_ascii("") == ""


@pytest.mark.parametrize("source", ("é" * 1024, b"x" * 2048))
def test_safe_sample_limits_bytes(source):
    expected = source.encode() if isinstance(source, str) else source
    assert utils.safe_sample(source) == expected[:1024]


def test_dummy_response_preserves_response_context():
    headers = CaseInsensitiveDict({"Content-Type": "text/html"})
    response = utils.DummyResponse(
        text="HTML",
        url="https://example.com/",
        status_code=201,
        encoding="utf-8",
        elapsed_seconds=1.5,
        headers=headers,
        content=b"HTML",
    )
    assert response.text == "HTML"
    assert response.content == b"HTML"
    assert response.url == "https://example.com/"
    assert response.status_code == 201
    assert response.elapsed == datetime.timedelta(seconds=1.5)
    assert response.headers is headers
    assert response.encoding == "utf-8"
    assert response.history == []


def test_dummy_response_derives_encoding_before_using_fallback():
    response = utils.DummyResponse(
        text='<meta charset="utf-8">',
        derive_encoding=True,
        default_encoding="ascii",
    )
    assert response.encoding == "utf-8"
    assert utils.DummyResponse(default_encoding="ascii").encoding == "ascii"


@pytest.mark.parametrize(
    "url",
    (
        "https://example.com",
        "https://example.com/",
        "https://example.com/plain",
    ),
)
def test_fix_unicode_url_preserves_already_valid_paths(url):
    assert utils.fix_unicode_url(url) == url


def test_fix_unicode_url_returns_original_when_quoting_fails(monkeypatch, caplog):
    url = "https://example.com/café"
    monkeypatch.setattr(utils, "url_quote", Mock(side_effect=ValueError("bad path")))
    assert utils.fix_unicode_url(url, urlparser=urlparse) == url
    assert "fix_unicode_url failure" in caplog.text


def test_response_history_preserves_redirect_order_for_logging():
    first = utils.DummyResponse(url="http://example.com/", status_code=301)
    last = utils.DummyResponse(url="https://example.com/", status_code=200)
    last.history = [first]
    history = utils.ResponseHistory(last)
    assert history.history == [(301, first.url), (200, last.url)]
    logger = Mock()
    history.log(prefix="Redirect", logger=logger)
    assert [call[0][1:] for call in logger.call_args_list] == [
        ("Redirect", 0, 301, first.url),
        ("Redirect", 1, 200, last.url),
    ]


@pytest.mark.parametrize("strict", (True, False))
def test_future_warning_can_be_promoted_to_error(monkeypatch, strict):
    monkeypatch.setattr(config, "FUTURE_BEHAVIOR", strict)
    with pytest.warns(FutureWarning, match="Upcoming change"):
        if strict:
            with pytest.raises(ValueError, match="Upcoming change"):
                utils.warn_future("Upcoming change")
        else:
            utils.warn_future("Upcoming change")


def test_user_warning():
    with pytest.warns(UserWarning, match="Check configuration"):
        utils.warn_user("Check configuration")
