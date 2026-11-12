"""Adversarial selection tests using one document with competing metadata."""

# stdlib
from copy import deepcopy
from itertools import permutations
from pathlib import Path

# pypi
import pytest

# local
from metadata_parser import MetadataParser
from metadata_parser import ParsedResult
from metadata_parser.exceptions import InvalidStrategy

# Independent expectations; do not derive priority or values from the parser.
DEFAULT_ORDER = ("meta", "page", "og", "dc", "twitter")
ORDERS = [order for size in range(1, 6) for order in permutations(DEFAULT_ORDER, size)]
EXPECTED = {
    "title": {
        "meta": ["Meta title first", "Meta title second", "Meta title body"],
        "page": ["Page title first"],
        "og": ["OG title first", "OG title second"],
        "dc": ["DC title first", "DC title second"],
        "twitter": ["Twitter title first", "Twitter title second"],
    },
    "description": {
        "meta": ["Meta description"],
        "og": ["OG description"],
        "dc": ["DC description"],
        "twitter": ["Twitter description"],
    },
    "creator": {"meta": ["Meta creator"], "dc": ["DC creator"]},
    "keywords": {"og": ["OG keywords"], "twitter": ["Twitter keywords"]},
    "canonical": {"page": ["https://example.com/page-canonical"]},
    "image": {
        "page": ["https://example.com/page-image.jpg"],
        "og": ["https://example.com/og-image.jpg"],
        "twitter": ["https://example.com/twitter-image.jpg"],
    },
    "empty-first": {
        "meta": ["", "Meta nonempty second"],
        "dc": ["", "DC nonempty second"],
        "og": ["OG nonempty fallback"],
    },
    "missing": {},
}


@pytest.fixture(scope="module")
def shared_document():
    path = Path(__file__).parent / "html_scaffolds" / "strategy_selection.html"
    return path.read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def shared_result(shared_document):
    return MetadataParser(html=shared_document).parsed_result


@pytest.fixture
def isolated_result(shared_result):
    # Exercise the same candidates without letting encoder/strategy tests mutate
    # the shared result. Copy only metadata, not the BeautifulSoup document.
    result = ParsedResult()
    result.metadata = deepcopy(shared_result.metadata)
    result.strategy = list(DEFAULT_ORDER)
    return result


def expected_first(field, order):
    for store in order:
        if store in EXPECTED[field]:
            return EXPECTED[field][store][0]
    return None


@pytest.mark.parametrize("field", EXPECTED)
def test_shared_document_candidates_match_fixture_intent(shared_result, field):
    candidates = shared_result.get_metadatas(field, strategy="all")
    if not EXPECTED[field]:
        assert candidates is None
        return
    flattened = {
        store: [value["content"] if store == "dc" else value for value in values]
        for store, values in candidates.items()
    }
    assert flattened == EXPECTED[field]


@pytest.mark.parametrize("field", EXPECTED)
@pytest.mark.parametrize("order", ORDERS, ids=["-".join(order) for order in ORDERS])
def test_every_ordered_strategy_subset(shared_result, field, order):
    strategy = list(order)
    before = deepcopy(shared_result.metadata)
    assert shared_result.select_first_match(field, strategy) == expected_first(
        field, order
    )
    # Selection must not reorder a caller's strategy or consume stored values.
    assert strategy == list(order)
    assert shared_result.metadata == before


@pytest.mark.parametrize("order", ORDERS, ids=["-".join(order) for order in ORDERS])
def test_constructor_strategy_becomes_default(shared_document, order):
    strategy = list(order)
    result = MetadataParser(html=shared_document, strategy=strategy).parsed_result
    assert result.select_first_match("title") == EXPECTED["title"][order[0]][0]
    assert strategy == list(order)
    # An explicit lookup must override the constructor's restricted strategy.
    assert result.select_first_match("title", ["meta"]) == "Meta title first"
    assert result.select_first_match("title", "all") == "Meta title first"
    assert result.select_first_match("title") == EXPECTED["title"][order[0]][0]


@pytest.mark.parametrize("field", EXPECTED)
@pytest.mark.parametrize("strategy", (None, "all"))
def test_default_and_all_order(shared_result, field, strategy):
    assert shared_result.select_first_match(field, strategy) == expected_first(
        field, DEFAULT_ORDER
    )


@pytest.mark.parametrize(
    "order", (("dc", "meta", "dc"), ("page", "page"), ("twitter", "og", "twitter"))
)
def test_repeated_strategies_do_not_change_priority(shared_result, order):
    assert (
        shared_result.select_first_match("title", list(order))
        == EXPECTED["title"][order[0]][0]
    )


@pytest.mark.parametrize(
    "strategy",
    (
        "meta",
        "unknown",
        ["all"],
        ["meta", "unknown"],
        ["meta", "_internal"],
        ["meta", "_v"],
    ),
)
@pytest.mark.parametrize("field", ("title", "missing"))
def test_invalid_strategy_is_rejected_even_with_earlier_match(
    shared_result, strategy, field
):
    with pytest.raises(InvalidStrategy):
        shared_result.select_first_match(field, strategy)


def test_dublin_core_returns_content_without_modifying_attributes(shared_result):
    before = deepcopy(shared_result.metadata["dc"]["title"])
    assert shared_result.select_first_match("title", ["dc"]) == "DC title first"
    assert before[0] == {"content": "DC title first", "lang": "en", "scheme": "example"}
    assert shared_result.metadata["dc"]["title"] == before


@pytest.mark.parametrize("strategy", (["meta", "og"], ["dc", "og"]))
def test_empty_first_value_is_preserved_not_skipped(shared_result, strategy):
    assert shared_result.select_first_match("empty-first", strategy) == ""


@pytest.mark.parametrize("strategy", (None, [], ""))
def test_falsy_strategy_uses_configured_default(isolated_result, strategy):
    # Characterize the current API: an empty strategy means use the default,
    # rather than search no stores. Keep that behavior explicit.
    isolated_result.strategy = ["twitter", "meta"]
    assert (
        isolated_result.select_first_match("title", strategy) == "Twitter title first"
    )


@pytest.mark.parametrize("store", DEFAULT_ORDER)
def test_default_encoder_receives_correct_store_and_value(isolated_result, store):
    seen = []

    def encoder(value, strategy):
        seen.append((deepcopy(value), strategy))
        text = value["content"] if strategy == "dc" else value
        return text.upper()

    isolated_result.default_encoder = encoder
    before = deepcopy(isolated_result.metadata)
    assert (
        isolated_result.select_first_match("title", [store])
        == EXPECTED["title"][store][0].upper()
    )
    assert [strategy for _, strategy in seen] == [store] * len(EXPECTED["title"][store])
    if store == "dc":
        assert seen[0][0] == before["dc"]["title"][0]
    assert isolated_result.metadata == before


def test_encoder_returning_unexpected_dict_fails_explicitly(isolated_result):
    isolated_result.default_encoder = lambda value, strategy: {"content": value}
    with pytest.raises(ValueError, match="unknown dict handling for strategy=`meta`"):
        isolated_result.select_first_match("title", ["meta"])


def test_encoded_dublin_core_dict_is_unwrapped(isolated_result):
    isolated_result.default_encoder = lambda value, strategy: {
        "content": value["content"].upper()
    }
    assert isolated_result.select_first_match("title", ["dc"]) == "DC TITLE FIRST"
