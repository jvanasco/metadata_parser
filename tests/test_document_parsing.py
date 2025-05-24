# stdlib
import os
from typing import Dict
import unittest
import warnings

# local
import metadata_parser

# ==============================================================================


# this bit lets us run the tests directly during development
_tests_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _tests_dir.endswith("metadata_parser"):
    _tests_dir = os.path.join(_tests_dir, "tests")
_examples_dir = os.path.join(_tests_dir, "html_scaffolds")

# cache these lazily
CACHED_FILESYSTEM_DOCUMENTS = {}


doc_base = """<html><head>%(head)s</head><body></body></html>"""

docs: Dict = {
    "good-canonical-absolute": {
        "url-real": """http://example.com""",
        "head": {
            "url-canonical": """http://example.com/canonical.html""",
            "url-og": None,
        },
        "expected": {"get_discrete_url()": "http://example.com/canonical.html"},
    },
    "good-og-absolute": {
        "url-real": """http://example.com""",
        "head": {"url-canonical": None, "url-og": """http://example.com/og.html"""},
        "expected": {"get_discrete_url()": "http://example.com/og.html"},
    },
    "good-canonical-noscheme-http": {
        "url-real": """http://example.com""",
        "head": {"url-canonical": """//example.com/canonical.html""", "url-og": None},
        "expected": {"get_discrete_url()": "http://example.com/canonical.html"},
    },
    "good-og-noscheme-http": {
        "url-real": """http://example.com""",
        "head": {"url-canonical": None, "url-og": """//example.com/og.html"""},
        "expected": {"get_discrete_url()": "http://example.com/og.html"},
    },
    "good-canonical-noscheme-https": {
        "url-real": """https://example.com""",
        "head": {"url-canonical": """//example.com/canonical.html""", "url-og": None},
        "expected": {"get_discrete_url()": "https://example.com/canonical.html"},
    },
    "good-og-noscheme-https": {
        "url-real": """https://example.com""",
        "head": {"url-canonical": None, "url-og": """//example.com/og.html"""},
        "expected": {"get_discrete_url()": "https://example.com/og.html"},
    },
    "good-canonical-relative": {
        "url-real": """http://example.com""",
        "head": {"url-canonical": """canonical.html""", "url-og": None},
        "expected": {"get_discrete_url()": "http://example.com/canonical.html"},
    },
    "good-canonical-relative_alt": {
        "url-real": """http://example.com""",
        "head": {"url-canonical": """/canonical.html""", "url-og": None},
        "expected": {"get_discrete_url()": "http://example.com/canonical.html"},
    },
    "good-og-relative_alt": {
        "url-real": """http://example.com""",
        "head": {"url-canonical": None, "url-og": """/og.html"""},
        "expected": {"get_discrete_url()": "http://example.com/og.html"},
    },
    "bad-canonical": {
        "url-real": """http://example.com/one-two-three.html""",
        "head": {"url-canonical": """...""", "url-og": None},
        "expected": {"get_discrete_url()": "http://example.com/one-two-three.html"},
    },
    "bad-canonical2": {
        "url-real": """http://example.com/one-two-three.html""",
        "head": {"url-canonical": """http://""", "url-og": None},
        "expected": {"get_discrete_url()": "http://example.com/one-two-three.html"},
    },
    "bad-canonical3": {
        "url-real": """http://example.com/one-two-three.html""",
        "head": {"url-canonical": """http://contentcreation""", "url-og": None},
        "expected": {"get_discrete_url()": "http://example.com/one-two-three.html"},
    },
    "bad-og": {
        "url-real": """http://example.com/one-two-three.html""",
        "head": {"url-canonical": None, "url-og": """..."""},
        "expected": {"get_discrete_url()": "http://example.com/one-two-three.html"},
    },
    "image-https": {
        "url-real": """https://example.com""",
        "head": {
            "url-canonical": """https://example.com/canonical.html""",
            "url-og": None,
            "url-og:image": """https://example.com/img.gif""",
        },
        "expected": {"og:image": """https://example.com/img.gif"""},
    },
    "image-https-noscheme": {
        "url-real": """https://example.com""",
        "head": {
            "url-canonical": """https://example.com/canonical.html""",
            "url-og": None,
            "url-og:image": """//example.com/img.gif""",
        },
        "expected": {"og:image": """https://example.com/img.gif"""},
    },
    "image-https-noscheme-secure": {
        "url-real": """https://example.com""",
        "head": {
            "url-canonical": """https://example.com/canonical.html""",
            "url-og": None,
            "url-og:image:secure_url": """//example.com/img.gif""",
        },
        "expected": {"og:image:secure_url": """https://example.com/img.gif"""},
    },
    "image-http": {
        "url-real": """http://example.com""",
        "head": {
            "url-canonical": """http://example.com/canonical.html""",
            "url-og": None,
            "url-og:image": """http://example.com/img.gif""",
        },
        "expected": {"og:image": """http://example.com/img.gif"""},
    },
    "image-http-noscheme": {
        "url-real": """http://example.com""",
        "head": {
            "url-canonical": """http://example.com/canonical.html""",
            "url-og": None,
            "url-og:image": """//example.com/img.gif""",
        },
        "expected": {"og:image": """http://example.com/img.gif"""},
    },
    "image-http-noscheme-secure": {
        "url-real": """http://example.com""",
        "head": {
            "url-canonical": """//example.com/canonical.html""",
            "url-og": None,
            "url-og:image:secure_url": """//example.com/img.gif""",
        },
        "expected": {"og:image:secure_url": None},
    },
}


def encoder_capitalizer(decoded):
    if type(decoded) is dict:
        return {k.upper(): v.upper() for k, v in decoded.items()}
    return decoded.upper()


# setup the test_docs with html bodies
for test in list(docs.keys()):
    head = ""
    if "url-og" in docs[test]["head"]:
        if docs[test]["head"]["url-og"] is not None:
            head += (
                """<meta property="og:url" content="%s"/>"""
                % docs[test]["head"]["url-og"]
            )
    if "url-canonical" in docs[test]["head"]:
        if docs[test]["head"]["url-canonical"] is not None:
            head += (
                """<link rel="canonical" href="%s" />"""
                % docs[test]["head"]["url-canonical"]
            )
    if "url-og:image" in docs[test]["head"]:
        if docs[test]["head"]["url-og:image"] is not None:
            head += (
                """<meta property="og:image" content="%s" />"""
                % docs[test]["head"]["url-og:image"]
            )
    if "url-og:image:secure_url" in docs[test]["head"]:
        if docs[test]["head"]["url-og:image:secure_url"] is not None:
            head += (
                """<meta property="og:image:secure_url" content="%s" />"""
                % docs[test]["head"]["url-og:image:secure_url"]
            )
    custom_vars = {"head": head}
    docs[test]["doc"] = doc_base % custom_vars


def _docs_test(test_names):
    errors = []
    for test in test_names:
        tests = []
        url = docs[test]["url-real"]
        parsed = metadata_parser.MetadataParser(url=url, html=docs[test]["doc"])
        if "get_discrete_url()" in docs[test]["expected"]:
            tests.append("get_discrete_url()")
            url_expected = docs[test]["expected"]["get_discrete_url()"]
            url_retrieved = parsed.get_discrete_url()
            if url_retrieved != url_expected:
                errors.append([test, "get_discrete_url()", url_expected, url_retrieved])
        if "og:image" in docs[test]["expected"]:
            tests.append("og:image")
            url_expected = docs[test]["expected"]["og:image"]
            url_retrieved = parsed.get_metadata_link("og:image")
            if url_retrieved != url_expected:
                errors.append([test, "og:image", url_expected, url_retrieved])
        if "og:image:secure_url" in docs[test]["expected"]:
            tests.append("og:image:secure_url")
            url_expected = docs[test]["expected"]["og:image:secure_url"]
            url_retrieved = parsed.get_metadata_link("og:image:secure_url")
            if url_retrieved != url_expected:
                errors.append(
                    [test, "og:image:secure_url", url_expected, url_retrieved]
                )
        if not tests:
            raise ValueError("No tests!")
    return errors


def _docs_test_parser(test_names, cached_urlparser, cached_urlparser_maxitems=None):
    errors = []
    for test in test_names:
        tests = []
        url = docs[test]["url-real"]
        kwargs = {}
        if cached_urlparser != "*no-kwarg":
            kwargs["cached_urlparser"] = cached_urlparser
        if cached_urlparser_maxitems is not None:
            kwargs["cached_urlparser_maxitems"] = cached_urlparser_maxitems
        parsed = metadata_parser.MetadataParser(
            url=url, html=docs[test]["doc"], **kwargs
        )
        if "get_discrete_url()" in docs[test]["expected"]:
            tests.append("get_discrete_url()")
            url_expected = docs[test]["expected"]["get_discrete_url()"]
            url_retrieved = parsed.get_discrete_url()
            if url_retrieved != url_expected:
                errors.append([test, "get_discrete_url()", url_expected, url_retrieved])
        if not tests:
            raise ValueError("No tests!")
    return errors


class TestHtmlDocument(unittest.TestCase):
    """
    python -m unittest tests.document_parsing.TestHtmlDocument.test_get_discrete_url__good_relative
    python -m unittest tests.document_parsing.TestHtmlDocument.test_get_discrete_url__good_absolute
    python -m unittest tests.document_parsing.TestHtmlDocument.test_get_discrete_url__bad
    """

    def test_get_discrete_url__good_relative(self):
        errors = _docs_test(
            [
                "good-canonical-relative",
                "good-canonical-relative_alt",
                "good-og-relative_alt",
            ]
        )
        if errors:
            raise ValueError(errors)

    def test_get_discrete_url__good_absolute(self):
        errors = _docs_test(["good-canonical-absolute", "good-og-absolute"])
        if errors:
            raise ValueError(errors)

    def test_get_discrete_url__good_noscheme(self):
        errors = _docs_test(
            [
                "good-canonical-noscheme-http",
                "good-og-noscheme-http",
                "good-canonical-noscheme-https",
                "good-og-noscheme-https",
            ]
        )
        if errors:
            raise ValueError(errors)

    def test_get_discrete_url__bad(self):
        errors = _docs_test(
            ["bad-canonical", "bad-canonical2", "bad-canonical3", "bad-og"]
        )
        if errors:
            raise ValueError(errors)

    def test_get_image(self):
        errors = _docs_test(
            [
                "image-http-noscheme-secure",
                "image-https-noscheme-secure",
                "image-http",
                "image-https",
                "image-http-noscheme",
                "image-https-noscheme",
            ]
        )
        if errors:
            raise ValueError(errors)


class TestEncoders(unittest.TestCase):
    """
    python -munittest tests.test_document_parsing.TestEncoders
    """

    _data = {
        "unicode_whitespace": {
            "raw": """Example line with\xa0unicode whitespace.""",
            "ascii": """Example line with unicode whitespace.""",
        },
        "unicode_chars": {
            "raw": """Example line with\xc2\xa0unicode chars.""",
            "ascii": """Example line withA unicode chars.""",
        },
        "decode_html_encoder": {
            "html": """<html><head><meta name="description" content="Foo&amp;nbsp;Bar, &amp;quot;Biz Bang Bash.&amp;quot;"/></head></html>""",
            "parsed": "Foo&nbsp;Bar, &quot;Biz Bang Bash.&quot;",
            "decoded": 'Foo Bar, "Biz Bang Bash."',
        },
    }

    def _make_raw(self, data_option):
        # create a parsed result, and inject raw data.
        # data coming through beautifulsoup will be parsed differently
        parsed = metadata_parser.MetadataParser()
        parsed.metadata["meta"]["title"] = self._data[data_option]["raw"]
        return parsed

    def _make_html(self, data_option, default_encoder=None):
        # data coming through beautifulsoup is parsed by that library
        parsed = metadata_parser.MetadataParser(
            html=self._data[data_option]["html"],
            force_doctype=True,
            default_encoder=default_encoder,
        )
        return parsed

    def test_unicode_whitespace(self):
        parsed = self._make_raw("unicode_whitespace")
        # title_raw = parsed.get_metadata('title')
        title_ascii = parsed.get_metadata("title", encoder=metadata_parser.encode_ascii)
        self.assertEqual(title_ascii, self._data["unicode_whitespace"]["ascii"])

    def test_unicode_chars(self):
        parsed = self._make_raw("unicode_chars")
        # title_raw = parsed.get_metadata('title')
        title_ascii = parsed.get_metadata("title", encoder=metadata_parser.encode_ascii)
        self.assertEqual(title_ascii, self._data["unicode_chars"]["ascii"])

    def test_decode_html_encoder(self):
        parsed = self._make_html("decode_html_encoder")
        parsed_description = parsed.get_metadata("description")

        decoded_direct = metadata_parser.decode_html(parsed_description)
        self.assertEqual(decoded_direct, self._data["decode_html_encoder"]["decoded"])

        decoded_decoder = parsed.get_metadata(
            "description", encoder=metadata_parser.decode_html
        )
        self.assertEqual(decoded_decoder, self._data["decode_html_encoder"]["decoded"])

    def test_default_encoder(self):
        """
        ensure the default decoder is invoked
        """
        parsed_with_default = self._make_html(
            "decode_html_encoder", default_encoder=metadata_parser.decode_html
        )
        parsed_no_default = self._make_html("decode_html_encoder")

        # does the default_decoder work?
        decoded_default = parsed_with_default.get_metadata("description")
        self.assertEqual(decoded_default, self._data["decode_html_encoder"]["decoded"])

        # does the no decoder work as expected?
        not_decoded = parsed_no_default.get_metadata("description")
        self.assertEqual(not_decoded, self._data["decode_html_encoder"]["parsed"])

        # can we override the default_decoder to get RAW?
        decoded_override = parsed_with_default.get_metadata(
            "description", encoder="raw"
        )
        self.assertEqual(decoded_override, self._data["decode_html_encoder"]["parsed"])

        # can we override the default_decoder to get something else?
        # ensure these 2 aren't equal, otherwise the next bit doesn't really test!
        self.assertNotEqual(
            self._data["decode_html_encoder"]["parsed"],
            self._data["decode_html_encoder"]["parsed"].upper(),
        )
        decoded_override = parsed_with_default.get_metadata(
            "description", encoder=lambda x: x.upper()
        )
        self.assertEqual(
            decoded_override, self._data["decode_html_encoder"]["parsed"].upper()
        )


class TestDocumentParsing(unittest.TestCase):
    """
    python -m unittest tests.document_parsing.TestDocumentParsing
    python -m unittest tests.document_parsing.TestDocumentParsing.test_simple_html
    python -m unittest tests.document_parsing.TestDocumentParsing.test_html_urls
    python -m unittest tests.document_parsing.TestDocumentParsing.test_complex_html
    python -m unittest tests.document_parsing.TestDocumentParsing.test_charsets
    """

    def _MakeOne(self, filename):
        """lazy cache of files as needed"""
        global CACHED_FILESYSTEM_DOCUMENTS
        if filename not in CACHED_FILESYSTEM_DOCUMENTS:
            CACHED_FILESYSTEM_DOCUMENTS[filename] = open(
                os.path.join(_examples_dir, filename)
            ).read()
        return CACHED_FILESYSTEM_DOCUMENTS[filename]

    def test_simple_html(self):
        """this tests simple.html to have certain fields"""
        html = self._MakeOne("simple.html")
        parsed = metadata_parser.MetadataParser(url=None, html=html)
        self.assertEqual(
            parsed.metadata["meta"]["article:publisher"],
            "https://www.example.com/meta/property=article:publisher",
        )
        self.assertEqual(parsed.metadata["meta"]["author"], "meta.author")
        self.assertEqual(parsed.metadata["meta"]["description"], "meta.description")
        self.assertEqual(parsed.metadata["meta"]["keywords"], "meta.keywords")
        self.assertEqual(
            parsed.metadata["meta"]["og:description"], "meta.property=og:description"
        )
        self.assertEqual(
            parsed.metadata["meta"]["og:image"],
            "https://www.example.com/meta/property=og:image",
        )
        self.assertEqual(
            parsed.metadata["meta"]["og:site_name"], "meta.property=og:site_name"
        )
        self.assertEqual(parsed.metadata["meta"]["og:title"], "meta.property=og:title")
        self.assertEqual(parsed.metadata["meta"]["og:type"], "meta.property=og:type")
        self.assertEqual(
            parsed.metadata["meta"]["og:url"],
            "https://www.example.com/meta/property=og:url",
        )
        self.assertEqual(
            parsed.metadata["meta"]["twitter:card"], "meta.name=twitter:card"
        )
        self.assertEqual(
            parsed.metadata["meta"]["twitter:description"],
            "meta.name=twitter:description",
        )
        self.assertEqual(
            parsed.metadata["meta"]["twitter:image:src"],
            "https://example.com/meta/name=twitter:image:src",
        )
        self.assertEqual(
            parsed.metadata["meta"]["twitter:site"], "meta.name=twitter:site"
        )
        self.assertEqual(
            parsed.metadata["meta"]["twitter:title"], "meta.name=twitter:title"
        )
        self.assertEqual(
            parsed.metadata["meta"]["twitter:url"],
            "https://example.com/meta/name=twitter:url",
        )
        self.assertEqual(
            parsed.metadata["og"]["description"], "meta.property=og:description"
        )
        self.assertEqual(
            parsed.metadata["og"]["image"],
            "https://www.example.com/meta/property=og:image",
        )
        self.assertEqual(
            parsed.metadata["og"]["site_name"], "meta.property=og:site_name"
        )
        self.assertEqual(parsed.metadata["og"]["title"], "meta.property=og:title")
        self.assertEqual(parsed.metadata["og"]["type"], "meta.property=og:type")
        self.assertEqual(
            parsed.metadata["og"]["url"], "https://www.example.com/meta/property=og:url"
        )
        self.assertEqual(
            parsed.metadata["page"]["canonical"],
            "http://example.com/meta/rel=canonical",
        )
        self.assertEqual(
            parsed.metadata["page"]["shortlink"],
            "http://example.com/meta/rel=shortlink",
        )
        self.assertEqual(parsed.metadata["page"]["title"], "title")
        self.assertEqual(parsed.metadata["twitter"]["card"], "meta.name=twitter:card")
        self.assertEqual(
            parsed.metadata["twitter"]["description"], "meta.name=twitter:description"
        )
        self.assertEqual(
            parsed.metadata["twitter"]["image:src"],
            "https://example.com/meta/name=twitter:image:src",
        )
        self.assertEqual(parsed.metadata["twitter"]["site"], "meta.name=twitter:site")
        self.assertEqual(parsed.metadata["twitter"]["title"], "meta.name=twitter:title")
        self.assertEqual(
            parsed.metadata["twitter"]["url"],
            "https://example.com/meta/name=twitter:url",
        )
        self.assertEqual(
            parsed.metadata["twitter"]["data"], "meta.name=twitter:data||value"
        )
        self.assertNotIn("label", parsed.metadata["twitter"])
        self.assertEqual(parsed.is_opengraph_minimum(), True)

    def test_html_urls(self):
        """this tests simple.html to have certain fields"""
        html = self._MakeOne("simple.html")
        parsed = metadata_parser.MetadataParser(url=None, html=html)
        # by default we do og_first
        self.assertEqual(
            parsed.get_discrete_url(), "https://www.example.com/meta/property=og:url"
        )
        self.assertEqual(
            parsed.get_discrete_url(canonical_first=True, og_first=False),
            "http://example.com/meta/rel=canonical",
        )
        self.assertEqual(
            parsed.get_url_opengraph(), "https://www.example.com/meta/property=og:url"
        )
        self.assertEqual(
            parsed.get_url_canonical(), "http://example.com/meta/rel=canonical"
        )

    def test_encoding_fallback(self):
        """this tests simple.html to have certain fields"""
        html = """<html><head></head><body>body</body></html>"""
        parsed = metadata_parser.MetadataParser(url=None, html=html)
        # typing scope
        assert parsed.response is not None
        self.assertEqual(parsed.response.encoding, "ISO-8859-1")

    def test_encoding_declared(self):
        html = """<html><head><meta charset="UTF-8"></head><body>body</body></html>"""
        parsed = metadata_parser.MetadataParser(url=None, html=html)
        # typing scope
        assert parsed.response is not None
        self.assertEqual(parsed.response.encoding, "UTF-8")

    def test_complex_html(self):
        """
        this tests duplicates.html to have certain fields

        this also ensures some legacy behavior is supported

        such as calling both:
            * `parsed.parsed_result.get_metadatas`
            * `parsed.get_metadatas`
        """
        html = self._MakeOne("duplicates.html")
        parsed = metadata_parser.MetadataParser(url=None, html=html)

        # this is just a property and should be the same object
        self.assertIs(parsed.metadata, parsed.parsed_result.metadata)

        # we should be tracking the verison now
        self.assertIn("_v", parsed.metadata)

        # it should be the same version
        self.assertEqual(parsed.metadata_version, metadata_parser.ParsedResult._version)
        self.assertEqual(
            parsed.parsed_result.metadata_version, metadata_parser.ParsedResult._version
        )

        # we have 3 og:image entries in this file
        _computed_link = parsed.get_metadata_link("image", strategy=["og"])
        assert _computed_link == "https://www.example.com/meta/property=og:image"
        _all_og_images = parsed.get_metadatas("og:image")
        assert _all_og_images is not None
        assert len(_all_og_images) == 3
        assert "https://www.example.com/meta/property=og:image" in _all_og_images
        # bs4 cleans up the ampersand internally into an entity, but prints it deserialized by default
        assert (
            "https://www.example.com/meta?property=og:image&duplicate=1"
            in _all_og_images
        )
        assert (
            "https://www.example.com/meta?property=og:image&duplicate=2"
            in _all_og_images
        )

        # -----
        # this is a duplicate element and should be stored in the metadata dict as a list
        _citation_authors = [
            "citation_author:1",
            "citation_author:2",
            "citation_author:3",
        ]
        # these should be lists
        self.assertEqual(parsed.metadata["meta"]["citation_author"], _citation_authors)
        self.assertEqual(
            parsed.parsed_result.get_metadatas("citation_author", ["meta"]),
            _citation_authors,
        )
        self.assertEqual(
            parsed.get_metadatas("citation_author", ["meta"]), _citation_authors
        )
        # this is a string
        self.assertEqual(
            parsed.parsed_result.get_metadata("citation_author", ["meta"]),
            _citation_authors[0],
        )
        self.assertEqual(
            parsed.get_metadata("citation_author", ["meta"]), _citation_authors[0]
        )

        _meta_authors = ["meta.author:1", "meta.author:2"]
        # these should be lists
        self.assertEqual(parsed.metadata["meta"]["author"], _meta_authors)
        self.assertEqual(
            parsed.parsed_result.get_metadatas("author", ["meta"]), _meta_authors
        )
        self.assertEqual(parsed.get_metadatas("author", ["meta"]), _meta_authors)
        # this is a string
        self.assertEqual(
            parsed.parsed_result.get_metadata("author", ["meta"]), _meta_authors[0]
        )
        self.assertEqual(parsed.get_metadata("author", ["meta"]), _meta_authors[0])

        _meta_kws = ["meta.keywords:1", "meta.keywords:2"]
        # these should be lists
        self.assertEqual(parsed.metadata["meta"]["keywords"], _meta_kws)
        self.assertEqual(
            parsed.parsed_result.get_metadatas("keywords", ["meta"]), _meta_kws
        )
        self.assertEqual(parsed.get_metadatas("keywords", ["meta"]), _meta_kws)
        # this is a string
        self.assertEqual(
            parsed.parsed_result.get_metadata("keywords", ["meta"]), _meta_kws[0]
        )
        self.assertEqual(parsed.get_metadata("keywords", ["meta"]), _meta_kws[0])

        # -----
        # this is a single element and should be stored in the metadata dict as a string
        _description = "meta.description"

        # these should be lists
        self.assertEqual(
            parsed.parsed_result.get_metadatas("description", ["meta"]), [_description]
        )
        self.assertEqual(parsed.get_metadatas("description", ["meta"]), [_description])

        # this is a string
        self.assertEqual(parsed.metadata["meta"]["description"], _description)
        self.assertEqual(
            parsed.parsed_result.get_metadata("description", ["meta"]), _description
        )
        self.assertEqual(parsed.get_metadata("description", ["meta"]), _description)

        # -----
        # dc creator has a language variant
        #  'dc': {'Creator': [{'content': 'Plato'},
        #                     {'content': 'Platon', 'lang': 'fr'}],

        self.assertIn("Creator", parsed.metadata["dc"])
        dc_creator = parsed.metadata["dc"]["Creator"]
        # so this should be a list
        self.assertIs(type(dc_creator), list)
        # with a length of 2
        self.assertEqual(len(dc_creator), 2)
        self.assertIs(type(dc_creator[0]), dict)
        self.assertIs(type(dc_creator[1]), dict)
        self.assertIn("content", dc_creator[0])
        self.assertEqual(dc_creator[0]["content"], "Plato")
        self.assertIn("content", dc_creator[1])
        self.assertEqual(dc_creator[1]["content"], "Platon")
        self.assertIn("lang", dc_creator[1])
        self.assertEqual(dc_creator[1]["lang"], "fr")

        # -----
        # dc subject has a scheme variant
        # 'Subject': [{'content': 'heart attack'},
        #             {'content': 'Myocardial Infarction; Pericardial Effusion',
        #              'scheme': 'MESH'},
        #             {'content': 'vietnam war'},
        #             {'content': 'Vietnamese Conflict, 1961-1975',
        #              'scheme': 'LCSH'},
        #             {'content': 'Friendship'},
        #             {'content': '158.25', 'scheme': 'ddc'}]},
        dcSubjectsExpected = [
            {"content": "heart attack"},
            {
                "content": "Myocardial Infarction; Pericardial Effusion",
                "scheme": "MESH",
            },
            {"content": "vietnam war"},
            {"content": "Vietnamese Conflict, 1961-1975", "scheme": "LCSH"},
            {"content": "Friendship"},
            {"content": "158.25", "scheme": "ddc"},
        ]
        self.assertIn("Subject", parsed.metadata["dc"])
        dc_subject = parsed.metadata["dc"]["Subject"]
        self.assertIs(type(dc_subject), list)
        self.assertEqual(len(dc_subject), len(dcSubjectsExpected))
        for idx, _expected in enumerate(dc_subject):
            self.assertIs(type(dc_subject[idx]), dict)
            self.assertEqual(
                len(dc_subject[idx].keys()), len(dcSubjectsExpected[idx].keys())
            )
            self.assertEqual(
                sorted(dc_subject[idx].keys()), sorted(dcSubjectsExpected[idx].keys())
            )
            for _key in dc_subject[idx].keys():
                self.assertEqual(dc_subject[idx][_key], dcSubjectsExpected[idx][_key])

        # -----
        # dc TestMixedCandidates1
        # handle the ordering of results
        # the raw info tested is the same as the above Subject test...
        dcTestMixedCandidates1aExpected = {"content": "Friendship"}
        self.assertIn("TestMixedCandidates1a", parsed.metadata["dc"])
        dc_mixed_candidates = parsed.metadata["dc"]["TestMixedCandidates1a"]
        self.assertIs(type(dc_mixed_candidates), dict)
        self.assertEqual(
            len(dc_mixed_candidates.keys()), len(dcTestMixedCandidates1aExpected.keys())
        )
        self.assertEqual(
            sorted(dc_mixed_candidates.keys()),
            sorted(dcTestMixedCandidates1aExpected.keys()),
        )
        for _key in dc_mixed_candidates.keys():
            self.assertEqual(
                dc_mixed_candidates[_key], dcTestMixedCandidates1aExpected[_key]
            )
        # but we need to test get_metadata and get_metadatas
        with self.assertRaises(ValueError) as cm:
            parsed.get_metadata("TestMixedCandidates1a", strategy="dc")
        self.assertEqual(
            cm.exception.args[0], "If `strategy` is not a `list`, it must be 'all'."
        )

        self.assertEqual(
            parsed.get_metadata("TestMixedCandidates1a", strategy=["dc"]), "Friendship"
        )
        self.assertEqual(
            parsed.get_metadatas("TestMixedCandidates1a", strategy=["dc"]),
            [dcTestMixedCandidates1aExpected],
        )
        self.assertEqual(
            parsed.get_metadata(
                "TestMixedCandidates1a", strategy=["dc"], encoder=encoder_capitalizer
            ),
            "FRIENDSHIP",
        )
        self.assertEqual(
            parsed.get_metadatas(
                "TestMixedCandidates1a", strategy=["dc"], encoder=encoder_capitalizer
            ),
            [{"CONTENT": "FRIENDSHIP"}],
        )

        # 1b
        dcTestMixedCandidates1bExpected = {"content": "158.25", "scheme": "ddc"}
        self.assertIn("TestMixedCandidates1b", parsed.metadata["dc"])
        dc_mixed_candidates = parsed.metadata["dc"]["TestMixedCandidates1b"]
        self.assertIs(type(dc_mixed_candidates), dict)
        self.assertEqual(
            len(dc_mixed_candidates.keys()), len(dcTestMixedCandidates1bExpected.keys())
        )
        self.assertEqual(
            sorted(dc_mixed_candidates.keys()),
            sorted(dcTestMixedCandidates1bExpected.keys()),
        )
        for _key in dc_mixed_candidates.keys():
            self.assertEqual(
                dc_mixed_candidates[_key], dcTestMixedCandidates1bExpected[_key]
            )
        # but we need to test get_metadata and get_metadatas
        self.assertEqual(
            parsed.get_metadata("TestMixedCandidates1b", strategy=["dc"]), "158.25"
        )
        self.assertEqual(
            parsed.get_metadatas("TestMixedCandidates1b", strategy=["dc"]),
            [dcTestMixedCandidates1bExpected],
        )
        self.assertEqual(
            parsed.get_metadata(
                "TestMixedCandidates1b", strategy=["dc"], encoder=encoder_capitalizer
            ),
            "158.25",
        )
        self.assertEqual(
            parsed.get_metadatas(
                "TestMixedCandidates1b", strategy=["dc"], encoder=encoder_capitalizer
            ),
            [{"CONTENT": "158.25", "SCHEME": "DDC"}],
        )

        # -----
        # dc TestMixedCandidates2
        # handle the ordering of results
        # the raw info tested is the same as the above Subject test...
        dcTestMixedCandidates2aExpected = [
            {"content": "158.25", "scheme": "ddc"},
            {"content": "Friendship"},
        ]
        self.assertIn("TestMixedCandidates2a", parsed.metadata["dc"])
        dc_mixed_candidates = parsed.metadata["dc"]["TestMixedCandidates2a"]
        self.assertIs(type(dc_mixed_candidates), list)
        self.assertEqual(len(dc_mixed_candidates), len(dcTestMixedCandidates2aExpected))
        for idx, _expected in enumerate(dc_mixed_candidates):
            self.assertIs(type(dc_mixed_candidates[idx]), dict)
            self.assertEqual(
                len(dc_mixed_candidates[idx].keys()),
                len(dcTestMixedCandidates2aExpected[idx].keys()),
            )
            self.assertEqual(
                sorted(dc_mixed_candidates[idx].keys()),
                sorted(dcTestMixedCandidates2aExpected[idx].keys()),
            )
            for _key in dc_mixed_candidates[idx].keys():
                self.assertEqual(
                    dc_mixed_candidates[idx][_key],
                    dcTestMixedCandidates2aExpected[idx][_key],
                )
        # but we need to test get_metadata and get_metadatas

        self.assertEqual(
            parsed.get_metadata("TestMixedCandidates2a", strategy=["dc"]), "Friendship"
        )
        self.assertEqual(
            parsed.get_metadatas("TestMixedCandidates2a", strategy=["dc"]),
            dcTestMixedCandidates2aExpected,
        )
        self.assertEqual(
            parsed.get_metadata(
                "TestMixedCandidates2a", strategy=["dc"], encoder=encoder_capitalizer
            ),
            "FRIENDSHIP",
        )
        self.assertEqual(
            parsed.get_metadatas(
                "TestMixedCandidates2a", strategy=["dc"], encoder=encoder_capitalizer
            ),
            [{"CONTENT": "158.25", "SCHEME": "DDC"}, {"CONTENT": "FRIENDSHIP"}],
        )

        # 2b
        dcTestMixedCandidates2bExpected = [
            {"content": "Friendship"},
            {"content": "158.25", "scheme": "ddc"},
        ]
        self.assertIn("TestMixedCandidates2b", parsed.metadata["dc"])
        dc_mixed_candidates = parsed.metadata["dc"]["TestMixedCandidates2b"]
        self.assertIs(type(dc_mixed_candidates), list)
        self.assertEqual(len(dc_mixed_candidates), len(dcTestMixedCandidates2bExpected))
        for idx, _expected in enumerate(dc_mixed_candidates):
            self.assertIs(type(dc_mixed_candidates[idx]), dict)
            self.assertEqual(
                len(dc_mixed_candidates[idx].keys()),
                len(dcTestMixedCandidates2bExpected[idx].keys()),
            )
            self.assertEqual(
                sorted(dc_mixed_candidates[idx].keys()),
                sorted(dcTestMixedCandidates2bExpected[idx].keys()),
            )
            for _key in dc_mixed_candidates[idx].keys():
                self.assertEqual(
                    dc_mixed_candidates[idx][_key],
                    dcTestMixedCandidates2bExpected[idx][_key],
                )
        # but we need to test get_metadata and get_metadatas
        self.assertEqual(
            parsed.get_metadata("TestMixedCandidates2b", strategy=["dc"]), "Friendship"
        )
        self.assertEqual(
            parsed.get_metadatas("TestMixedCandidates2b", strategy=["dc"]),
            dcTestMixedCandidates2bExpected,
        )
        self.assertEqual(
            parsed.get_metadata(
                "TestMixedCandidates2b", strategy=["dc"], encoder=encoder_capitalizer
            ),
            "FRIENDSHIP",
        )
        self.assertEqual(
            parsed.get_metadatas(
                "TestMixedCandidates2b", strategy=["dc"], encoder=encoder_capitalizer
            ),
            [{"CONTENT": "FRIENDSHIP"}, {"CONTENT": "158.25", "SCHEME": "DDC"}],
        )

        # ok, mixedfield tests:
        # TestMixedField0
        self.assertEqual(parsed.get_metadata("TestMixedField0", strategy=["dc"]), None)
        self.assertEqual(
            parsed.get_metadata("TestMixedField0", strategy=["meta"]),
            "meta:TestMixedField0",
        )
        self.assertEqual(
            parsed.get_metadata("TestMixedField0", strategy="all"),
            {"meta": "meta:TestMixedField0"},
        )
        self.assertEqual(
            parsed.get_metadata(
                "TestMixedField0", strategy=["dc"], encoder=encoder_capitalizer
            ),
            None,
        )
        self.assertEqual(
            parsed.get_metadata(
                "TestMixedField0", strategy=["meta"], encoder=encoder_capitalizer
            ),
            "META:TESTMIXEDFIELD0",
        )
        self.assertEqual(
            parsed.get_metadata(
                "TestMixedField0", strategy="all", encoder=encoder_capitalizer
            ),
            {"meta": "META:TESTMIXEDFIELD0"},
        )
        self.assertEqual(parsed.get_metadatas("TestMixedField0", strategy=["dc"]), None)
        self.assertEqual(
            parsed.get_metadatas("TestMixedField0", strategy=["meta"]),
            ["meta:TestMixedField0"],
        )
        self.assertEqual(
            parsed.get_metadatas("TestMixedField0", strategy="all"),
            {"meta": ["meta:TestMixedField0"]},
        )
        self.assertEqual(
            parsed.get_metadatas(
                "TestMixedField0", strategy=["dc"], encoder=encoder_capitalizer
            ),
            None,
        )
        self.assertEqual(
            parsed.get_metadatas(
                "TestMixedField0", strategy=["meta"], encoder=encoder_capitalizer
            ),
            ["META:TESTMIXEDFIELD0"],
        )
        self.assertEqual(
            parsed.get_metadatas(
                "TestMixedField0", strategy="all", encoder=encoder_capitalizer
            ),
            {"meta": ["META:TESTMIXEDFIELD0"]},
        )

        # TestMixedField1
        self.assertEqual(
            parsed.get_metadata("TestMixedField1", strategy=["dc"]),
            "dc:TestMixedField1",
        )
        self.assertEqual(
            parsed.get_metadata("TestMixedField1", strategy=["meta"]),
            "meta:TestMixedField1",
        )
        self.assertEqual(
            parsed.get_metadata("TestMixedField1", strategy="all"),
            {"meta": "meta:TestMixedField1", "dc": "dc:TestMixedField1"},
        )
        self.assertEqual(
            parsed.get_metadata(
                "TestMixedField1", strategy=["dc"], encoder=encoder_capitalizer
            ),
            "DC:TESTMIXEDFIELD1",
        )
        self.assertEqual(
            parsed.get_metadata(
                "TestMixedField1", strategy=["meta"], encoder=encoder_capitalizer
            ),
            "META:TESTMIXEDFIELD1",
        )
        self.assertEqual(
            parsed.get_metadata(
                "TestMixedField1", strategy="all", encoder=encoder_capitalizer
            ),
            {"meta": "META:TESTMIXEDFIELD1", "dc": "DC:TESTMIXEDFIELD1"},
        )
        self.assertEqual(
            parsed.get_metadatas("TestMixedField1", strategy=["dc"]),
            [{"content": "dc:TestMixedField1"}],
        )
        self.assertEqual(
            parsed.get_metadatas("TestMixedField1", strategy=["meta"]),
            ["meta:TestMixedField1"],
        )
        self.assertEqual(
            parsed.get_metadatas("TestMixedField1", strategy="all"),
            {
                "meta": ["meta:TestMixedField1"],
                "dc": [{"content": "dc:TestMixedField1"}],
            },
        )
        self.assertEqual(
            parsed.get_metadatas(
                "TestMixedField1", strategy=["dc"], encoder=encoder_capitalizer
            ),
            [{"CONTENT": "DC:TESTMIXEDFIELD1"}],
        )
        self.assertEqual(
            parsed.get_metadatas(
                "TestMixedField1", strategy=["meta"], encoder=encoder_capitalizer
            ),
            ["META:TESTMIXEDFIELD1"],
        )
        self.assertEqual(
            parsed.get_metadatas(
                "TestMixedField1", strategy="all", encoder=encoder_capitalizer
            ),
            {
                "meta": ["META:TESTMIXEDFIELD1"],
                "dc": [{"CONTENT": "DC:TESTMIXEDFIELD1"}],
            },
        )
        # TestMixedField2
        self.assertEqual(
            parsed.get_metadata("TestMixedField2", strategy=["dc"]),
            "dc:TestMixedField2",
        )
        self.assertEqual(
            parsed.get_metadata("TestMixedField2", strategy=["meta"]),
            "meta:TestMixedField2",
        )
        self.assertEqual(
            parsed.get_metadata("TestMixedField2", strategy="all"),
            {"meta": "meta:TestMixedField2", "dc": "dc:TestMixedField2"},
        )
        self.assertEqual(
            parsed.get_metadata(
                "TestMixedField2", strategy=["dc"], encoder=encoder_capitalizer
            ),
            "DC:TESTMIXEDFIELD2",
        )
        self.assertEqual(
            parsed.get_metadata(
                "TestMixedField2", strategy=["meta"], encoder=encoder_capitalizer
            ),
            "META:TESTMIXEDFIELD2",
        )
        self.assertEqual(
            parsed.get_metadata(
                "TestMixedField2", strategy="all", encoder=encoder_capitalizer
            ),
            {"meta": "META:TESTMIXEDFIELD2", "dc": "DC:TESTMIXEDFIELD2"},
        )
        self.assertEqual(
            parsed.get_metadatas("TestMixedField2", strategy=["dc"]),
            [
                {"content": "dc:TestMixedField2"},
                {"content": "dc:TestMixedField2.ddc", "scheme": "ddc"},
            ],
        )
        self.assertEqual(
            parsed.get_metadatas("TestMixedField2", strategy=["meta"]),
            ["meta:TestMixedField2"],
        )
        self.assertEqual(
            parsed.get_metadatas("TestMixedField2", strategy="all"),
            {
                "meta": ["meta:TestMixedField2"],
                "dc": [
                    {"content": "dc:TestMixedField2"},
                    {"content": "dc:TestMixedField2.ddc", "scheme": "ddc"},
                ],
            },
        )
        self.assertEqual(
            parsed.get_metadatas(
                "TestMixedField2", strategy=["dc"], encoder=encoder_capitalizer
            ),
            [
                {"CONTENT": "DC:TESTMIXEDFIELD2"},
                {"CONTENT": "DC:TESTMIXEDFIELD2.DDC", "SCHEME": "DDC"},
            ],
        )
        self.assertEqual(
            parsed.get_metadatas(
                "TestMixedField2", strategy=["meta"], encoder=encoder_capitalizer
            ),
            ["META:TESTMIXEDFIELD2"],
        )
        self.assertEqual(
            parsed.get_metadatas(
                "TestMixedField2", strategy="all", encoder=encoder_capitalizer
            ),
            {
                "meta": ["META:TESTMIXEDFIELD2"],
                "dc": [
                    {"CONTENT": "DC:TESTMIXEDFIELD2"},
                    {"CONTENT": "DC:TESTMIXEDFIELD2.DDC", "SCHEME": "DDC"},
                ],
            },
        )

        # TestMixedField3
        self.assertEqual(
            parsed.get_metadata("TestMixedField3", strategy=["dc"]),
            "dc:TestMixedField3",
        )
        self.assertEqual(
            parsed.get_metadata("TestMixedField3", strategy=["meta"]),
            "meta:TestMixedField3",
        )
        self.assertEqual(
            parsed.get_metadata("TestMixedField3", strategy="all"),
            {"meta": "meta:TestMixedField3", "dc": "dc:TestMixedField3"},
        )
        self.assertEqual(
            parsed.get_metadata(
                "TestMixedField3", strategy=["dc"], encoder=encoder_capitalizer
            ),
            "DC:TESTMIXEDFIELD3",
        )
        self.assertEqual(
            parsed.get_metadata(
                "TestMixedField3", strategy=["meta"], encoder=encoder_capitalizer
            ),
            "META:TESTMIXEDFIELD3",
        )
        self.assertEqual(
            parsed.get_metadata(
                "TestMixedField3", strategy="all", encoder=encoder_capitalizer
            ),
            {"meta": "META:TESTMIXEDFIELD3", "dc": "DC:TESTMIXEDFIELD3"},
        )
        self.assertEqual(
            parsed.get_metadatas("TestMixedField3", strategy=["dc"]),
            [{"content": "dc:TestMixedField3"}],
        )
        self.assertEqual(
            parsed.get_metadatas("TestMixedField3", strategy=["meta"]),
            ["meta:TestMixedField3"],
        )
        self.assertEqual(
            parsed.get_metadatas("TestMixedField3", strategy="all"),
            {
                "meta": ["meta:TestMixedField3"],
                "dc": [{"content": "dc:TestMixedField3"}],
            },
        )
        self.assertEqual(
            parsed.get_metadatas(
                "TestMixedField3", strategy=["dc"], encoder=encoder_capitalizer
            ),
            [{"CONTENT": "DC:TESTMIXEDFIELD3"}],
        )
        self.assertEqual(
            parsed.get_metadatas(
                "TestMixedField3", strategy=["meta"], encoder=encoder_capitalizer
            ),
            ["META:TESTMIXEDFIELD3"],
        )
        self.assertEqual(
            parsed.get_metadatas(
                "TestMixedField3", strategy="all", encoder=encoder_capitalizer
            ),
            {
                "meta": ["META:TESTMIXEDFIELD3"],
                "dc": [{"CONTENT": "DC:TESTMIXEDFIELD3"}],
            },
        )

        self.assertEqual(parsed.get_metadata("news_keywords", strategy=["meta"]), "")
        self.assertEqual(
            parsed.get_metadata("auto-publish", strategy=["meta"]), "timely"
        )
        self.assertEqual(
            parsed.get_metadata("article:modified_time", strategy=["meta"]),
            "2017-10-11 01:01:01",
        )
        self.assertEqual(
            parsed.get_metadata("msapplication-tap-highlight", strategy=["meta"]), "no"
        )
        self.assertEqual(
            parsed.get_metadata("google-site-verification", strategy=["meta"]),
            "123123123",
        )
        self.assertEqual(
            parsed.get_metadata("twitter:data1", strategy=["meta"]), "8 min read"
        )
        self.assertEqual(
            parsed.get_metadata("google", strategy=["meta"]), "notranslate"
        )
        self.assertEqual(parsed.get_metadata("news_keywords", strategy=["meta"]), "")
        self.assertEqual(
            parsed.get_metadatas("viewport", strategy=["meta"]),
            [
                "width=device-width,initial-scale=1,maximum-scale=1,user-scalable=no",
                "width=device-width, initial-scale=1, maximum-scale=1",
            ],
        )
        self.assertEqual(
            parsed.get_metadata("thumbnail", strategy=["meta"]),
            "https://example.com/path/to/image.jpg",
        )
        self.assertEqual(
            parsed.get_metadata_link("thumbnail", strategy=["meta"]),
            "https://example.com/path/to/image.jpg",
        )
        self.assertEqual(
            parsed.get_metadata("thumbnail-2", strategy=["meta"]),
            "//example.com/path/to/image.jpg",
        )
        self.assertEqual(
            parsed.get_metadata_link("thumbnail-2", strategy=["meta"]), None
        )
        self.assertEqual(
            parsed.get_metadata("thumbnail-3", strategy=["meta"]), "/path/to/image.jpg"
        )
        self.assertEqual(
            parsed.get_metadata_link("thumbnail-3", strategy=["meta"]), None
        )

        # this should error!
        with self.assertRaises(ValueError) as cm:
            parsed.get_metadatas("canonical", strategy=["all"])
        self.assertEqual(
            cm.exception.args[0], 'Submit "all" as a `str`, not in a `list`.'
        )

        # ok, now test the return types
        # some behavior was changed in the .7 release

        # get_metadata - single section
        self.assertEqual(
            parsed.get_metadata("canonical", strategy=["page"]),
            "http://example.com/meta/rel=canonical",
        )
        self.assertEqual(parsed.get_metadata("canonical", strategy=["meta"]), None)
        self.assertEqual(
            parsed.get_metadata("canonical", strategy="all"),
            {"page": "http://example.com/meta/rel=canonical"},
        )

        # get_metadatas - single section
        self.assertEqual(
            parsed.get_metadatas("canonical", strategy=["page"]),
            [
                "http://example.com/meta/rel=canonical",
            ],
        )
        self.assertEqual(parsed.get_metadatas("canonical", strategy=["meta"]), None)
        self.assertEqual(
            parsed.get_metadatas("canonical", strategy="all"),
            {
                "page": [
                    "http://example.com/meta/rel=canonical",
                ]
            },
        )

        # get_metadata - multiple section
        self.assertEqual(
            parsed.get_metadata("description", strategy=["meta"]), "meta.description"
        )
        self.assertEqual(
            parsed.get_metadata("description", strategy="all"),
            {
                "og": "meta.property=og:description",
                "meta": "meta.description",
                "twitter": "meta.name=twitter:description",
            },
        )
        # get_metadatas - multiple section
        self.assertEqual(
            parsed.get_metadatas("description", strategy=["meta"]), ["meta.description"]
        )
        self.assertEqual(
            parsed.get_metadatas("description", strategy="all"),
            {
                "og": [
                    "meta.property=og:description",
                ],
                "meta": [
                    "meta.description",
                ],
                "twitter": ["meta.name=twitter:description"],
            },
        )

        # multiple candidates!
        self.assertEqual(
            parsed.get_metadata("keywords", strategy=["meta"]), "meta.keywords:1"
        )
        self.assertEqual(
            parsed.get_metadatas("keywords", strategy=["meta"]),
            ["meta.keywords:1", "meta.keywords:2"],
        )

    def test_malformed_twitter(self):
        """
        this tests simple.html to have certain fields
        python -munittest tests.document_parsing.TestDocumentParsing.test_malformed_twitter
        """
        html = self._MakeOne("simple.html")

        # the default behavior is to not support malformed
        # that means we should consult 'value' for data and 'label'
        # in `simple.html`, "label" (incorrectly) uses "content" and "data" uses "label"
        parsed = metadata_parser.MetadataParser(url=None, html=html)
        self.assertEqual(
            parsed.metadata["twitter"]["data"], "meta.name=twitter:data||value"
        )
        self.assertNotIn("label", parsed.metadata["twitter"])
        self.assertNotIn("invalid", parsed.metadata["twitter"])

        # now with `support_malformed` support we will load the label!
        parsed2 = metadata_parser.MetadataParser(
            url=None, html=html, support_malformed=True
        )
        self.assertEqual(
            parsed2.metadata["twitter"]["data"], "meta.name=twitter:data||value"
        )
        self.assertEqual(
            parsed2.metadata["twitter"]["label"], "meta.name=twitter:label||content"
        )
        self.assertEqual(
            parsed2.metadata["twitter"]["invalid"], "meta.name=twitter:invalid"
        )

        # try it with dupes...
        html_dupes = self._MakeOne("duplicates.html")
        parsed_dupe = metadata_parser.MetadataParser(url=None, html=html_dupes)
        # two items for each of data/label, but label is empty strings
        self.assertEqual(
            parsed_dupe.metadata["twitter"]["data"],
            ["meta.name=twitter:data||value,1", "meta.name=twitter:data||value,2"],
        )
        self.assertNotIn("label", parsed.metadata["twitter"])

        # everyone is happy when metadata is malformed!
        parsed_dupe = metadata_parser.MetadataParser(
            url=None, html=html_dupes, support_malformed=True
        )
        self.assertEqual(
            parsed_dupe.metadata["twitter"]["data"],
            ["meta.name=twitter:data||value,1", "meta.name=twitter:data||value,2"],
        )
        self.assertEqual(
            parsed_dupe.metadata["twitter"]["label"],
            [
                "meta.name=twitter:label||content,1",
                "meta.name=twitter:label||content,2",
            ],
        )

    def test_charsets(self):
        """
        python -m unittest tests.document_parsing.TestDocumentParsing.test_charsets
        """
        a_html = self._MakeOne("charset_a.html")
        a_parsed = metadata_parser.MetadataParser(url=None, html=a_html)
        self.assertEqual(
            a_parsed.metadata["meta"]["content-type"], "text/html; charset=UTF-8"
        )

        b_html = self._MakeOne("charset_b.html")
        b_parsed = metadata_parser.MetadataParser(url=None, html=b_html)
        self.assertEqual(b_parsed.metadata["meta"]["charset"], "UTF-8")

        c_html = self._MakeOne("charset_c.html")
        c_parsed = metadata_parser.MetadataParser(url=None, html=c_html)
        self.assertEqual(c_parsed.metadata["meta"]["charset"], "UTF-8")


class Test_UrlParserCacheable(unittest.TestCase):
    """
    python -m unittest tests.document_parsing.Test_UrlParserCacheable
    """

    def test__default(self):
        """MetadataParser()"""
        errors = _docs_test_parser(
            [
                "good-canonical-relative",
                "good-canonical-relative_alt",
                "good-og-relative_alt",
            ],
            "*no-kwarg",
        )
        if errors:
            raise ValueError(errors)

    def test__True(self):
        """MetadataParser(cached_urlparser=True)"""
        errors = _docs_test_parser(
            [
                "good-canonical-relative",
                "good-canonical-relative_alt",
                "good-og-relative_alt",
            ],
            True,
        )
        if errors:
            raise ValueError(errors)

    def test__Int_1(self):
        """MetadataParser(cached_urlparser=1)"""
        with warnings.catch_warnings(record=True) as warned:
            warnings.simplefilter("always")
            errors = _docs_test_parser(
                [
                    "good-canonical-relative",
                    "good-canonical-relative_alt",
                    "good-og-relative_alt",
                ],
                1,
            )
            if errors:
                raise ValueError(errors)
            assert len(warned) >= 1
            _found = False
            for w in warned:
                if isinstance(w.message, FutureWarning):
                    if w.message.args[0].startswith(
                        "Supplying an int to `cached_urlparser` to set maxitems is deprecated."
                    ):
                        _found = True
                        assert (
                            "Supply `cached_urlparser=True, cached_urlparser_maxitems=int` instead."
                            in w.message.args[0]
                        )
            assert _found is True

    def test__Int_0(self):
        """MetadataParser(cached_urlparser=1)"""
        with warnings.catch_warnings(record=True) as warned:
            warnings.simplefilter("always")
            errors = _docs_test_parser(
                [
                    "good-canonical-relative",
                    "good-canonical-relative_alt",
                    "good-og-relative_alt",
                ],
                0,
            )
            if errors:
                raise ValueError(errors)
            assert len(warned) >= 1
            _found = False
            for w in warned:
                if isinstance(w.message, FutureWarning):
                    if w.message.args[0].startswith(
                        "Supplying `0` to `cached_urlparser` to set maxitems is deprecated."
                    ):
                        _found = True
                        assert (
                            "Supply `cached_urlparser=False` instead"
                            in w.message.args[0]
                        )
            assert _found is True

    def test__None(self):
        errors = _docs_test_parser(
            [
                "good-canonical-relative",
                "good-canonical-relative_alt",
                "good-og-relative_alt",
            ],
            None,
        )
        if errors:
            raise ValueError(errors)

    def test__False(self):
        errors = _docs_test_parser(
            [
                "good-canonical-relative",
                "good-canonical-relative_alt",
                "good-og-relative_alt",
            ],
            False,
        )
        if errors:
            raise ValueError(errors)

    def test__CustomParser(self):
        custom_parser_obj = metadata_parser.UrlParserCacheable()
        custom_parser = custom_parser_obj.urlparse
        errors = _docs_test_parser(
            [
                "good-canonical-relative",
                "good-canonical-relative_alt",
                "good-og-relative_alt",
            ],
            custom_parser,
        )
        if errors:
            raise ValueError(errors)


class Test_UrlParserCacheable_MaxItems(unittest.TestCase):

    def test__default(self):
        """MetadataParser()"""
        errors = _docs_test_parser(
            [
                "good-canonical-relative",
                "good-canonical-relative_alt",
                "good-og-relative_alt",
            ],
            "*no-kwarg",
            cached_urlparser_maxitems=1,
        )
        if errors:
            raise ValueError(errors)

    def test__True(self):
        # this should fail
        errors = _docs_test_parser(
            [
                "good-canonical-relative",
                "good-canonical-relative_alt",
                "good-og-relative_alt",
            ],
            True,
            cached_urlparser_maxitems=1,
        )
        if errors:
            raise ValueError(errors)

    def test__False(self):
        # this should fail
        with self.assertRaises(ValueError) as cm:
            errors = _docs_test_parser(
                [
                    "good-canonical-relative",
                    "good-canonical-relative_alt",
                    "good-og-relative_alt",
                ],
                False,
                cached_urlparser_maxitems=1,
            )
            if errors:
                raise ValueError(errors)
        assert isinstance(cm.exception, ValueError)
        assert (
            cm.exception.args[0]
            == "`cached_urlparser_maxitems` requires `cached_urlparser=True`"
        )

    def test__Int_1(self):
        # this should fail
        with self.assertRaises(ValueError) as cm:
            errors = _docs_test_parser(
                [
                    "good-canonical-relative",
                    "good-canonical-relative_alt",
                    "good-og-relative_alt",
                ],
                1,
                cached_urlparser_maxitems=1,
            )
            if errors:
                raise ValueError(errors)
        assert isinstance(cm.exception, ValueError)
        assert (
            cm.exception.args[0]
            == "`cached_urlparser_maxitems` requires `cached_urlparser=True`"
        )

    def test__Int_0(self):
        # this should fail
        with self.assertRaises(ValueError) as cm:
            errors = _docs_test_parser(
                [
                    "good-canonical-relative",
                    "good-canonical-relative_alt",
                    "good-og-relative_alt",
                ],
                0,
                cached_urlparser_maxitems=1,
            )
            if errors:
                raise ValueError(errors)
        assert isinstance(cm.exception, ValueError)
        assert (
            cm.exception.args[0]
            == "`cached_urlparser_maxitems` requires `cached_urlparser=True`"
        )

    def test__None(self):
        # this should fail
        with self.assertRaises(ValueError) as cm:
            errors = _docs_test_parser(
                [
                    "good-canonical-relative",
                    "good-canonical-relative_alt",
                    "good-og-relative_alt",
                ],
                None,
                cached_urlparser_maxitems=1,
            )
            if errors:
                raise ValueError(errors)
        assert isinstance(cm.exception, ValueError)
        assert (
            cm.exception.args[0]
            == "`cached_urlparser_maxitems` requires `cached_urlparser=True`"
        )

    def test__CustomParser(self):
        # this should fail
        custom_parser_obj = metadata_parser.UrlParserCacheable()
        custom_parser = custom_parser_obj.urlparse
        with self.assertRaises(ValueError) as cm:
            errors = _docs_test_parser(
                [
                    "good-canonical-relative",
                    "good-canonical-relative_alt",
                    "good-og-relative_alt",
                ],
                custom_parser,
                cached_urlparser_maxitems=1,
            )
            if errors:
                raise ValueError(errors)
        assert isinstance(cm.exception, ValueError)
        assert (
            cm.exception.args[0]
            == "`cached_urlparser_maxitems` requires `cached_urlparser=True`"
        )
