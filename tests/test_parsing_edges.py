# stdlib
from types import SimpleNamespace
from urllib.parse import urlparse

# pypi
from bs4 import BeautifulSoup
import pytest

# local
import metadata_parser
from metadata_parser import MetadataParser
from metadata_parser.exceptions import InvalidDocument
from metadata_parser.exceptions import NotParsable


def parse_head(head, **kwargs):
    return MetadataParser(html="<html><head>%s</head></html>" % head, **kwargs)


@pytest.mark.parametrize(
    "rel,field",
    (
        ("image_src", "image"),
        ("canonical", "canonical"),
        ("shortlink", "shortlink"),
    ),
)
@pytest.mark.parametrize("attribute", ("href", "content", None))
def test_link_metadata_accepts_supported_attributes_and_skips_missing(
    rel, field, attribute
):
    attrs = '%s="/article"' % attribute if attribute else ""
    page = parse_head('<link rel="%s" %s>' % (rel, attrs))
    assert page.parsed_result.select_first_match(field, ["page"]) == (
        "/article" if attribute else None
    )


def test_long_titles_are_truncated():
    page = parse_head("<title>%s</title>" % ("x" * 300))
    assert page.parsed_result.select_first_match("title") == "x" * page.LEN_MAX_TITLE


def test_incomplete_opengraph_tag_does_not_discard_other_metadata():
    page = parse_head(
        '<meta property="og:title"><meta property="og:type" content="article">'
    )
    assert page.parsed_result.get_metadatas("title") is None
    assert page.parsed_result.select_first_match("type", ["og"]) == "article"


@pytest.mark.parametrize(
    "html,message",
    (
        ("<p>No document element</p>", "missing `doc` or `doc.html`"),
        ("<html><body>No head</body></html>", "missing `doc.html.head`"),
    ),
)
@pytest.mark.parametrize("raise_on_invalid", (True, False))
def test_invalid_document_respects_raise_option(html, message, raise_on_invalid):
    page = MetadataParser(search_head_only=True, raise_on_invalid=raise_on_invalid)
    soup = BeautifulSoup(html, "html.parser")
    if raise_on_invalid:
        with pytest.raises(InvalidDocument) as caught:
            page.parse(soup)
        assert message in str(caught.value)
    else:
        page.parse(soup)
        assert page.parsed_result.get_metadatas("title") is None
    assert page.parsed_result.soup is soup


def test_head_only_omits_body_meta_tags():
    soup = BeautifulSoup(
        "<html><head><title>Title</title></head><body>"
        '<meta name="description" content="Body"></body></html>',
        "html.parser",
    )
    page = MetadataParser(search_head_only=True)
    page.parse(soup)
    assert page.parsed_result.select_first_match("title") == "Title"
    assert page.parsed_result.get_metadatas("description") is None


@pytest.mark.parametrize("result", ("wrong result", None))
def test_custom_soup_factory_must_return_beautifulsoup(monkeypatch, result):
    page = MetadataParser()
    monkeypatch.setattr(page, "make_soup", lambda html, **kwargs: result)
    with pytest.raises(NotParsable, match="did not parse into BeautifulSoup") as caught:
        page.parse("<html></html>")
    assert caught.value.metadataParser is page


def test_soup_factory_failure_becomes_not_parsable(monkeypatch):
    def fail(html, **kwargs):
        raise ValueError("Parser unavailable")

    page = MetadataParser()
    monkeypatch.setattr(page, "make_soup", fail)
    with pytest.raises(NotParsable, match="could not parse into BeautifulSoup"):
        page.parse("<html></html>")


@pytest.mark.parametrize(
    "value,allow,expected",
    (
        ("data:image/png;base64,AAAA", False, None),
        ("data:image/png;base64,AAAA", True, "data:image/png;base64,AAAA"),
        ("<invalid>", False, None),
        ("//example.com/article", False, None),
    ),
)
def test_metadata_link_rejects_non_links_and_disallowed_schemeless_canonical(
    value, allow, expected
):
    page = MetadataParser()
    page.parsed_result._add_discovered("page", "canonical", value)
    assert page.get_metadata_link("canonical", allow_encoded_uri=allow) == expected


def test_missing_metadata_link_returns_none():
    assert MetadataParser().get_metadata_link("image") is None


def test_relative_metadata_link_can_use_internal_document_context():
    page = MetadataParser(url="http://localhost/dir/page", html="")
    page.parsed_result._add_discovered("og", "image", "image.jpg")
    assert page.get_metadata_link("image", require_public_global=False) == (
        "http://localhost/dir/image.jpg"
    )


@pytest.mark.parametrize(
    "method,store,field",
    (
        ("get_url_canonical", "page", "canonical"),
        ("get_url_opengraph", "og", "url"),
    ),
)
@pytest.mark.parametrize(
    "value,unicode_allowed,expected",
    (
        ("https://example.com/café", False, None),
        ("https://example.com/café", True, "https://example.com/caf%C3%A9"),
        ("https://example.com/?q=é", True, None),
    ),
)
def test_metadata_url_unicode_options(
    method, store, field, value, unicode_allowed, expected
):
    page = MetadataParser()
    page.parsed_result._add_discovered(store, field, value)
    assert (
        getattr(page, method)(
            require_public_global=False, allow_unicode_url=unicode_allowed
        )
        == expected
    )


@pytest.mark.parametrize(
    "value,expected",
    (("path?x=1#part", "/path?x=1#part"), ("https://example.com/", "/")),
)
def test_relative_url_reconstruction_preserves_query_and_fragment(value, expected):
    assert metadata_parser.parsed_to_relative(urlparse(value)) == expected


def test_relative_path_with_relative_base_uses_root():
    assert (
        metadata_parser.parsed_to_relative(urlparse("next"), urlparse("relative/base"))
        == "/next"
    )


@pytest.mark.parametrize(
    "url,expected", (("/path", True), ("https://example.com/path", False), ("", False))
)
def test_relative_url_detection(url, expected):
    assert metadata_parser.is_parsed_valid_relative(urlparse(url)) is expected


def test_hostname_validation_without_tldextract(monkeypatch):
    monkeypatch.setattr(metadata_parser, "USE_TLDEXTRACT", False)
    assert metadata_parser.is_hostname_valid("example.com")
    assert not metadata_parser.is_hostname_valid("invalid")
    assert not metadata_parser.is_hostname_valid("localhost", allow_localhosts=False)
    assert metadata_parser.is_parsed_valid_url(urlparse("https://example.com/"))


@pytest.mark.parametrize(
    "result,expected",
    (
        (SimpleNamespace(registered_domain="example.com"), True),
        (SimpleNamespace(registered_domain=""), False),
        (SimpleNamespace(top_domain_under_public_suffix="example.com"), True),
        (
            SimpleNamespace(
                top_domain_under_public_suffix="", registered_domain="example.com"
            ),
            False,
        ),
    ),
)
def test_hostname_validation_supports_tldextract_result_properties(
    monkeypatch: pytest.MonkeyPatch, result: SimpleNamespace, expected: bool
) -> None:
    """Both validators prefer the current property and accept legacy results."""
    tldextract = pytest.importorskip("tldextract")
    monkeypatch.setattr(metadata_parser, "USE_TLDEXTRACT", True)
    monkeypatch.setattr(metadata_parser, "tldextract", tldextract, raising=False)
    monkeypatch.setattr(tldextract, "extract", lambda hostname: result)
    assert metadata_parser.is_hostname_valid("example.com") is expected
    assert metadata_parser.is_parsed_valid_url(urlparse("https://example.com/")) is expected


def test_scheme_and_encoding_without_response():
    page = MetadataParser(default_encoding="utf-8")
    assert page._response_encoding() == "utf-8"
    assert page.get_url_scheme() is None
    page.url = "https://example.com/"
    assert page.get_url_scheme() == "https"
    with pytest.raises(ValueError, match="not a schemeless url"):
        page.upgrade_schemeless_url("/relative")
