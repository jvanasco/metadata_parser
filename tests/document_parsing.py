import metadata_parser

import unittest
import os


# this bit lets us run the tests directly during development
_tests_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if _tests_dir.endswith('metadata_parser'):
    _tests_dir = os.path.join(_tests_dir, 'tests')
_examples_dir = os.path.join(_tests_dir, 'html_scaffolds')

# cache these lazily
CACHED_FILESYSTEM_DOCUMENTS = {}


doc_base = """<html><head>%(head)s</head><body></body></html>"""

docs = {
    'good-canonical-absolute': {
        'url-real': """http://example.com""",
        'head': {
            'url-canonical': """http://example.com/canonical.html""",
            'url-og': None,
        },
        'expected': {
            'get_discrete_url()': 'http://example.com/canonical.html',
        },
    },
    'good-og-absolute': {
        'url-real': """http://example.com""",
        'head': {
            'url-canonical': None,
            'url-og': """http://example.com/og.html""",
        },
        'expected': {
            'get_discrete_url()': 'http://example.com/og.html',
        },
    },
    'good-canonical-relative': {
        'url-real': """http://example.com""",
        'head': {
            'url-canonical': """canonical.html""",
            'url-og': None,
        },
        'expected': {
            'get_discrete_url()': 'http://example.com/canonical.html',
        },
    },
    'good-canonical-relative_alt': {
        'url-real': """http://example.com""",
        'head': {
            'url-canonical': """/canonical.html""",
            'url-og': None,
        },
        'expected': {
            'get_discrete_url()': 'http://example.com/canonical.html',
        },
    },
    'good-og-relative_alt': {
        'url-real': """http://example.com""",
        'head': {
            'url-canonical': None,
            'url-og': """/og.html""",
        },
        'expected': {
            'get_discrete_url()': 'http://example.com/og.html',
        },
    },


    'bad-canonical': {
        'url-real': """http://example.com/one-two-three.html""",
        'head': {
            'url-canonical': """...""",
            'url-og': None,
        },
        'expected': {
            'get_discrete_url()': 'http://example.com/one-two-three.html',
        },
    },
    'bad-canonical2': {
        'url-real': """http://example.com/one-two-three.html""",
        'head': {
            'url-canonical': """http://""",
            'url-og': None,
        },
        'expected': {
            'get_discrete_url()': 'http://example.com/one-two-three.html',
        },
    },
    'bad-canonical3': {
        'url-real': """http://example.com/one-two-three.html""",
        'head': {
            'url-canonical': """http://contentcreation""",
            'url-og': None,
        },
        'expected': {
            'get_discrete_url()': 'http://example.com/one-two-three.html',
        },
    },
    'bad-og': {
        'url-real': """http://example.com/one-two-three.html""",
        'head': {
            'url-canonical': None,
            'url-og': """...""",
        },
        'expected': {
            'get_discrete_url()': 'http://example.com/one-two-three.html',
        },
    },
}

# setup the test_docs with html bodies
for test in docs.keys():
    head = ''
    if docs[test]['head']['url-og'] is not None:
        head += """<meta property="og:url" content="%s"/>""" % \
            docs[test]['head']['url-og']
    if docs[test]['head']['url-canonical'] is not None:
        head += """<link rel="canonical" href="%s" />""" % \
            docs[test]['head']['url-canonical']
    custom_vars = {'head': head}
    docs[test]['doc'] = doc_base % custom_vars


def _docs_test(test_names):
    errors = []
    for test in test_names:
        url = docs[test]['url-real']
        url_expected = docs[test]['expected']['get_discrete_url()']
        parsed = metadata_parser.MetadataParser(
            url=url,
            html=docs[test]['doc']
        )
        url_retrieved = parsed.get_discrete_url()
        if url_retrieved != url_expected:
            errors.append([test, url_expected, url_retrieved, ])
    return errors


class TestHtmlDocument(unittest.TestCase):
    """
        python -m unittest tests.document_parsing.TestHtmlDocument.test_get_discrete_url__good_relative
        python -m unittest tests.document_parsing.TestHtmlDocument.test_get_discrete_url__good_absolute
        python -m unittest tests.document_parsing.TestHtmlDocument.test_get_discrete_url__bad
    """

    def test_get_discrete_url__good_relative(self):
        errors = _docs_test(['good-canonical-relative',
                             'good-canonical-relative_alt',
                             'good-og-relative_alt', ]
                            )
        if errors:
            raise ValueError(errors)

    def test_get_discrete_url__good_absolute(self):
        errors = _docs_test(['good-canonical-absolute', 'good-og-absolute', ])
        if errors:
            raise ValueError(errors)

    def test_get_discrete_url__bad(self):
        errors = _docs_test(['bad-canonical',
                             'bad-canonical2',
                             'bad-canonical3',
                             'bad-og', ]
                            )
        if errors:
            raise ValueError(errors)


class TestFakedPayloads(unittest.TestCase):
    """
    python -m unittest tests.document_parsing.TestFakedPayloads
    """

    _data_a = {"raw": u"""Example line with\xa0unicode whitespace.""",
               "ascii": """Example line with unicode whitespace.""",
               }
    _data_b = {"raw": u"""Example line with\xc2\xa0unicode chars.""",
               "ascii": """Example line withA unicode chars.""",
               }

    def _make_a(self):
        parsed = metadata_parser.MetadataParser()
        parsed.metadata['meta']['title'] = self._data_a['raw']
        return parsed

    def _make_b(self):
        parsed = metadata_parser.MetadataParser()
        parsed.metadata['meta']['title'] = self._data_b['raw']
        return parsed

    def test_a(self):
        parsed = self._make_a()
        # title_raw = parsed.get_metadata('title')
        title_ascii = parsed.get_metadata('title', encoder=metadata_parser.encode_ascii)
        self.assertEqual(title_ascii, self._data_a['ascii'])

    def test_b(self):
        parsed = self._make_b()
        # title_raw = parsed.get_metadata('title')
        title_ascii = parsed.get_metadata('title', encoder=metadata_parser.encode_ascii)
        self.assertEqual(title_ascii, self._data_b['ascii'])


class TestDocumentParsing(unittest.TestCase):
    """
    python -m unittest tests.document_parsing.TestDocumentParsing
    python -m unittest tests.document_parsing.TestDocumentParsing.test_simple_html
    python -m unittest tests.document_parsing.TestDocumentParsing.test_html_urls
    """

    def _MakeOne(self, filename):
        """lazy cache of files as needed"""
        global CACHED_FILESYSTEM_DOCUMENTS
        if filename not in CACHED_FILESYSTEM_DOCUMENTS:
            CACHED_FILESYSTEM_DOCUMENTS[filename] = open(os.path.join(_examples_dir, filename)).read()
        return CACHED_FILESYSTEM_DOCUMENTS[filename]

    def test_simple_html(self):
        """this tests simple.html to have certain fields"""
        html = self._MakeOne('simple.html')
        parsed = metadata_parser.MetadataParser(url=None, html=html)
        self.assertEquals(parsed.metadata['meta']['article:publisher'], 'https://www.example.com/meta/property=article:publisher')
        self.assertEquals(parsed.metadata['meta']['author'], 'meta.author')
        self.assertEquals(parsed.metadata['meta']['description'], 'meta.description')
        self.assertEquals(parsed.metadata['meta']['keywords'], 'meta.keywords')
        self.assertEquals(parsed.metadata['meta']['og:description'], 'meta.property=og:description')
        self.assertEquals(parsed.metadata['meta']['og:image'], 'https://www.example.com/meta/property=og:image')
        self.assertEquals(parsed.metadata['meta']['og:site_name'], 'meta.property=og:site_name')
        self.assertEquals(parsed.metadata['meta']['og:title'], 'meta.property=og:title')
        self.assertEquals(parsed.metadata['meta']['og:type'], 'meta.property=og:type')
        self.assertEquals(parsed.metadata['meta']['og:url'], 'https://www.example.com/meta/property=og:url')
        self.assertEquals(parsed.metadata['meta']['twitter:card'], 'meta.name=twitter:card')
        self.assertEquals(parsed.metadata['meta']['twitter:description'], 'meta.name=twitter:description')
        self.assertEquals(parsed.metadata['meta']['twitter:image:src'], 'https://example.com/meta/name=twitter:image:src')
        self.assertEquals(parsed.metadata['meta']['twitter:site'], 'meta.name=twitter:site')
        self.assertEquals(parsed.metadata['meta']['twitter:title'], 'meta.name=twitter:title')
        self.assertEquals(parsed.metadata['meta']['twitter:url'], 'https://example.com/meta/name=twitter:url')
        self.assertEquals(parsed.metadata['og']['description'], 'meta.property=og:description')
        self.assertEquals(parsed.metadata['og']['image'], 'https://www.example.com/meta/property=og:image')
        self.assertEquals(parsed.metadata['og']['site_name'], 'meta.property=og:site_name')
        self.assertEquals(parsed.metadata['og']['title'], 'meta.property=og:title')
        self.assertEquals(parsed.metadata['og']['type'], 'meta.property=og:type')
        self.assertEquals(parsed.metadata['og']['url'], 'https://www.example.com/meta/property=og:url')
        self.assertEquals(parsed.metadata['page']['canonical'], 'http://example.com/meta/rel=canonical')
        self.assertEquals(parsed.metadata['page']['shortlink'], 'http://example.com/meta/rel=shortlink')
        self.assertEquals(parsed.metadata['page']['title'], 'title')
        self.assertEquals(parsed.metadata['twitter']['card'], 'meta.name=twitter:card')
        self.assertEquals(parsed.metadata['twitter']['description'], 'meta.name=twitter:description')
        self.assertEquals(parsed.metadata['twitter']['image:src'], 'https://example.com/meta/name=twitter:image:src')
        self.assertEquals(parsed.metadata['twitter']['site'], 'meta.name=twitter:site')
        self.assertEquals(parsed.metadata['twitter']['title'], 'meta.name=twitter:title')
        self.assertEquals(parsed.metadata['twitter']['url'], 'https://example.com/meta/name=twitter:url')
        self.assertEquals(parsed.is_opengraph_minimum(), True)


    def test_html_urls(self):
        """this tests simple.html to have certain fields"""
        html = self._MakeOne('simple.html')
        parsed = metadata_parser.MetadataParser(url=None, html=html)
        # by default we do og_first
        self.assertEquals(parsed.get_discrete_url(), 'https://www.example.com/meta/property=og:url')
        self.assertEquals(parsed.get_discrete_url(canonical_first=True, og_first=False), 'http://example.com/meta/rel=canonical')
        self.assertEquals(parsed.get_url_opengraph(), 'https://www.example.com/meta/property=og:url')
        self.assertEquals(parsed.get_url_canonical(), 'http://example.com/meta/rel=canonical')

