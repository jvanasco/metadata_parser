"""Candidate expectations for fallback reconstruction; these do not fetch URLs.

The strict-mode cases explore returning usable metadata or a filtered fallback,
otherwise None. They are proposed reconstruction semantics, not security-policy
requirements. The desired behavior is under discussion; no production change
is included, so these candidate expectations currently fail in some cases.
"""

# pypi
import pytest
import requests

# local
import metadata_parser


LOCAL_URLS = (
    "http://localhost/private",
    "http://127.0.0.1/private",
    "http://0.0.0.0/private",
    "http://[::1]/private",
    "http://[::]/private",
)
PUBLIC_URL = "https://example.com/source"


@pytest.fixture(autouse=True)
def no_network(monkeypatch):
    def unexpected_fetch(*args, **kwargs):
        pytest.fail("URL selection must not fetch a document")

    monkeypatch.setattr(requests.Session, "get", unexpected_fetch)
    if metadata_parser.USE_TLDEXTRACT:
        # Use the bundled suffix snapshot without network access or cache writes.
        extract = metadata_parser.tldextract.TLDExtract(
            suffix_list_urls=(), cache_dir=None
        )
        monkeypatch.setattr(metadata_parser.tldextract, "extract", extract)


def make_page(url=None, head=""):
    return metadata_parser.MetadataParser(
        url=url,
        html="<html><head>%s</head><body></body></html>" % head,
    )


@pytest.mark.parametrize("url", LOCAL_URLS)
def test_strict_fallback_rejects_local_source(url):
    page = make_page(url)
    assert page.get_fallback_url(allow_localhosts=False) is None
    assert page.get_discrete_url(require_public_global=True) is None


@pytest.mark.parametrize("url", LOCAL_URLS)
def test_permissive_fallback_preserves_local_source(url):
    assert make_page(url).get_discrete_url(require_public_global=False) == url


@pytest.mark.parametrize("strict", (True, False))
def test_public_source_is_preserved_without_metadata(strict):
    assert make_page(PUBLIC_URL).get_discrete_url(
        require_public_global=strict
    ) == PUBLIC_URL


def test_missing_source_and_metadata_returns_none():
    assert make_page().get_discrete_url() is None


@pytest.mark.parametrize(
    "head",
    (
        '<link rel="canonical" href="/article">',
        '<meta property="og:url" content="/article">',
        '<link rel="canonical" href="https://foo.local/article">',
    ),
)
def test_unusable_metadata_does_not_restore_local_fallback(head):
    assert make_page(LOCAL_URLS[0], head).get_discrete_url() is None


@pytest.mark.parametrize(
    "head",
    (
        '<link rel="canonical" href="https://example.com/article">',
        '<meta property="og:url" content="https://example.com/article">',
    ),
)
def test_public_metadata_is_usable_even_with_local_source(head):
    assert make_page(LOCAL_URLS[0], head).get_discrete_url() == (
        "https://example.com/article"
    )


def test_strict_fallback_uses_public_original_when_actual_url_is_local():
    page = make_page(PUBLIC_URL)
    # Model URL state after a redirect without making an HTTP request.
    page.url_actual = LOCAL_URLS[0]
    assert page.get_fallback_url(allow_localhosts=False) == PUBLIC_URL
    assert page.get_discrete_url() == PUBLIC_URL


def test_strict_fallback_prefers_public_actual_url():
    page = make_page(LOCAL_URLS[0])
    page.url_actual = PUBLIC_URL
    assert page.get_discrete_url() == PUBLIC_URL


@pytest.mark.parametrize(
    "head",
    (
        '<link rel="canonical" href="http://localhost/article">',
        '<meta property="og:url" content="http://localhost/article">',
    ),
)
def test_local_metadata_keeps_existing_public_remount_behavior(head):
    assert make_page(PUBLIC_URL, head).get_discrete_url() == (
        "https://example.com/article"
    )


@pytest.mark.parametrize(
    "url",
    (
        "http://10.0.0.1/private",
        "http://192.168.1.1/private",
    ),
)
def test_private_ipv4_is_currently_outside_localhost_filter(url):
    # Characterize existing scope, not an endorsement of these URLs for SSRF
    # prevention. Whether to broaden the policy is a separate API decision.
    page = make_page(url)
    assert page.get_fallback_url(allow_localhosts=False) == url
    assert page.get_discrete_url() == url
