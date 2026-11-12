"""Named entity regression cases for issue #65 and parser backend differences."""

# stdlib
from html import unescape
from html.entities import html5 as HTML5_ENTITIES
from importlib.metadata import version
import sys
from typing import Tuple

# pypi
from bs4 import BeautifulSoup
import pytest

# local
from metadata_parser import MetadataParser

# Explicit expectations: do not derive these using the entity decoder under test.
# Legacy names permit a missing semicolon; HTML5-only names generally do not.
COMMON_ENTITIES = (
    ("amp", "&", True),
    ("lt", "<", True),
    ("gt", ">", True),
    ("quot", '"', True),
    ("apos", "'", False),
    ("nbsp", "\u00a0", True),
    ("copy", "\u00a9", True),
    ("reg", "\u00ae", True),
    ("trade", "\u2122", False),
    ("euro", "\u20ac", False),
    ("pound", "\u00a3", True),
    ("yen", "\u00a5", True),
    ("cent", "\u00a2", True),
    ("curren", "\u00a4", True),
    ("sect", "\u00a7", True),
    ("para", "\u00b6", True),
    ("deg", "\u00b0", True),
    ("plusmn", "\u00b1", True),
    ("times", "\u00d7", True),
    ("divide", "\u00f7", True),
    ("micro", "\u00b5", True),
    ("frac12", "\u00bd", True),
    ("middot", "\u00b7", True),
    ("bull", "\u2022", False),
    ("hellip", "\u2026", False),
    ("ndash", "\u2013", False),
    ("mdash", "\u2014", False),
    ("lsquo", "\u2018", False),
    ("rsquo", "\u2019", False),
    ("ldquo", "\u201c", False),
    ("rdquo", "\u201d", False),
    ("laquo", "\u00ab", True),
    ("raquo", "\u00bb", True),
    ("eacute", "\u00e9", True),
    ("Eacute", "\u00c9", True),
    ("auml", "\u00e4", True),
    ("ouml", "\u00f6", True),
    ("uuml", "\u00fc", True),
    ("szlig", "\u00df", True),
    ("alpha", "\u03b1", False),
    ("pi", "\u03c0", False),
    ("larr", "\u2190", False),
    ("rarr", "\u2192", False),
    ("le", "\u2264", False),
    ("ge", "\u2265", False),
    ("ne", "\u2260", False),
    ("not", "\u00ac", True),
    ("notin", "\u2209", False),
    ("AMP", "&", True),
    ("Tab", "\u0009", False),
    ("NewLine", "\u000a", False),
    ("curlywedge", "\u22cf", False),
    ("NotEqualTilde", "\u2242\u0338", False),
)


def pytest_generate_tests(metafunc):
    if "html5_entity" not in metafunc.fixturenames:
        return
    if not metafunc.config.getoption("--html5-entities"):
        metafunc.parametrize(
            "html5_entity",
            [pytest.param(None, marks=pytest.mark.skip(reason="Use --html5-entities"))],
        )
        return
    # Python ships the HTML5 named-reference table, including legacy spellings.
    # Use the table as data, not html.unescape or any parser's decoder as oracle.
    names = sorted({name.rstrip(";") for name in HTML5_ENTITIES})
    metafunc.parametrize(
        "html5_entity",
        [(name, HTML5_ENTITIES[name + ";"], name in HTML5_ENTITIES) for name in names],
        ids=names,
    )


@pytest.fixture(params=("lxml", "html.parser", "html5lib"))
def parser_class(request):
    backend = request.param
    if backend == "html5lib":
        pytest.importorskip("html5lib", reason="Install the testing-backends extra")

    class BackendParser(MetadataParser):
        def make_soup(self, html, **kwargs_bs):
            # Select explicitly so a missing/broken backend cannot silently fall
            # back to another parser and produce a misleading passing result.
            soup = BeautifulSoup(html, backend, **kwargs_bs)
            assert soup.builder.NAME == backend
            return soup

    return backend, BackendParser


def test_default_parser_uses_lxml():
    # lxml is a required test dependency, rather than an optional skipped test.
    page = MetadataParser(html="<html><head><title>Title</title></head></html>")
    assert page.parsed_result.soup.builder.NAME == "lxml"
    assert page.parsed_result.select_first_match("title") == "Title"


def expected_title_text(backend, name, decoded, legacy, semicolon):
    if semicolon or legacy or backend == "html.parser":
        return decoded
    # lxml/html5lib consume the longest permitted legacy prefix in title text.
    # Example: &notin (no ;) becomes "\u00acin", whereas html.parser returns
    # "\u2209". In quoted attributes all backends preserve &notin literally.
    for length in range(len(name) - 1, 0, -1):
        prefix = name[:length]
        if prefix in HTML5_ENTITIES:
            return HTML5_ENTITIES[prefix] + name[length:]
    return "&" + name


def entity_failure_details(
    page: MetadataParser, backend: str, html: str, reference: str, legacy: bool
) -> str:
    """Capture parser output before metadata extraction on assertion failure."""
    soup = page.parsed_result.soup
    backend_version = sys.version if backend == "html.parser" else version(backend)
    title = soup.title
    parsed_title = title.get_text() if title is not None else None
    return (
        f"Python={sys.version}\n"
        f"BeautifulSoup={version('beautifulsoup4')}\n"
        f"backend={backend} ({backend_version}), builder={type(soup.builder)!r}\n"
        f"reference={reference!a}, legacy={legacy}, "
        f"html.unescape(reference)={unescape(reference)!a}\n"
        f"input HTML={html!a}\n"
        f"parsed title={parsed_title!a}\n"
        f"parsed meta attributes={[tag.attrs for tag in soup.find_all('meta')]!a}"
    )


def check_entity(
    parser_class: Tuple[str, type[MetadataParser]],
    name: str,
    decoded: str,
    legacy: bool,
    semicolon: bool,
) -> None:
    """Check title text and quoted attributes for the same entity reference."""
    backend, parser = parser_class
    reference = "&" + name + (";" if semicolon else "")
    expected_attribute = f"[{decoded if semicolon or legacy else reference}]"
    title_text = expected_title_text(backend, name, decoded, legacy, semicolon)
    expected_title = f"[{title_text}]"
    html = (
        f"<html><head><title>[{reference}]</title>"
        f'<meta name="description" content="[{reference}]">'
        f'<meta property="og:description" content="[{reference}]">'
        "</head></html>"
    )
    page = parser(html=html)
    # Surround with brackets to retain whitespace entities such as &nbsp;
    # through the package's normal metadata stripping.
    actual_title = page.parsed_result.select_first_match("title", ["page"])
    assert actual_title == expected_title, (
        f"title: expected={expected_title!a}, actual={actual_title!a}\n"
        + entity_failure_details(page, backend, html, reference, legacy)
    )
    for strategy in ("meta", "og"):
        actual = page.parsed_result.select_first_match("description", [strategy])
        assert actual == expected_attribute, (
            f"{strategy} description: expected={expected_attribute!a}, "
            f"actual={actual!a}\n"
            + entity_failure_details(page, backend, html, reference, legacy)
        )


@pytest.mark.parametrize(
    "name,decoded,legacy", COMMON_ENTITIES, ids=[name for name, _, _ in COMMON_ENTITIES]
)
@pytest.mark.parametrize("semicolon", (True, False), ids=("semicolon", "no-semicolon"))
def test_common_named_entities(parser_class, name, decoded, legacy, semicolon):
    check_entity(parser_class, name, decoded, legacy, semicolon)


@pytest.mark.html5_entities
@pytest.mark.parametrize("semicolon", (True, False), ids=("semicolon", "no-semicolon"))
def test_full_html5_named_entities(parser_class, html5_entity, semicolon):
    name, decoded, legacy = html5_entity
    check_entity(parser_class, name, decoded, legacy, semicolon)


@pytest.mark.parametrize("query", ("current=2", "currency=2", "amp=2"))
def test_entity_prefix_in_url_attribute_preserves_query_parameter(parser_class, query):
    _, parser = parser_class
    url = "https://example.com/?first=1&" + query
    page = parser(
        html=(
            '<html><head><link rel="canonical" href="%s">'
            '<meta property="og:url" content="%s"></head></html>'
        )
        % (url, url)
    )
    assert page.parsed_result.select_first_match("canonical", ["page"]) == url
    assert page.parsed_result.select_first_match("url", ["og"]) == url
