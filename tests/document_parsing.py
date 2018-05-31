import metadata_parser

import unittest
import os
if __debug__:
    # used when writing tests
    import pprint


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


def encoder_capitalizer(decoded):
    if type(decoded) == dict:
        return {k.upper(): v.upper() for k, v in decoded.items()}
    return decoded.upper()


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
    python -m unittest tests.document_parsing.TestDocumentParsing.test_complex_html
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
        self.assertEqual(parsed.metadata['meta']['article:publisher'], 'https://www.example.com/meta/property=article:publisher')
        self.assertEqual(parsed.metadata['meta']['author'], 'meta.author')
        self.assertEqual(parsed.metadata['meta']['description'], 'meta.description')
        self.assertEqual(parsed.metadata['meta']['keywords'], 'meta.keywords')
        self.assertEqual(parsed.metadata['meta']['og:description'], 'meta.property=og:description')
        self.assertEqual(parsed.metadata['meta']['og:image'], 'https://www.example.com/meta/property=og:image')
        self.assertEqual(parsed.metadata['meta']['og:site_name'], 'meta.property=og:site_name')
        self.assertEqual(parsed.metadata['meta']['og:title'], 'meta.property=og:title')
        self.assertEqual(parsed.metadata['meta']['og:type'], 'meta.property=og:type')
        self.assertEqual(parsed.metadata['meta']['og:url'], 'https://www.example.com/meta/property=og:url')
        self.assertEqual(parsed.metadata['meta']['twitter:card'], 'meta.name=twitter:card')
        self.assertEqual(parsed.metadata['meta']['twitter:description'], 'meta.name=twitter:description')
        self.assertEqual(parsed.metadata['meta']['twitter:image:src'], 'https://example.com/meta/name=twitter:image:src')
        self.assertEqual(parsed.metadata['meta']['twitter:site'], 'meta.name=twitter:site')
        self.assertEqual(parsed.metadata['meta']['twitter:title'], 'meta.name=twitter:title')
        self.assertEqual(parsed.metadata['meta']['twitter:url'], 'https://example.com/meta/name=twitter:url')
        self.assertEqual(parsed.metadata['og']['description'], 'meta.property=og:description')
        self.assertEqual(parsed.metadata['og']['image'], 'https://www.example.com/meta/property=og:image')
        self.assertEqual(parsed.metadata['og']['site_name'], 'meta.property=og:site_name')
        self.assertEqual(parsed.metadata['og']['title'], 'meta.property=og:title')
        self.assertEqual(parsed.metadata['og']['type'], 'meta.property=og:type')
        self.assertEqual(parsed.metadata['og']['url'], 'https://www.example.com/meta/property=og:url')
        self.assertEqual(parsed.metadata['page']['canonical'], 'http://example.com/meta/rel=canonical')
        self.assertEqual(parsed.metadata['page']['shortlink'], 'http://example.com/meta/rel=shortlink')
        self.assertEqual(parsed.metadata['page']['title'], 'title')
        self.assertEqual(parsed.metadata['twitter']['card'], 'meta.name=twitter:card')
        self.assertEqual(parsed.metadata['twitter']['description'], 'meta.name=twitter:description')
        self.assertEqual(parsed.metadata['twitter']['image:src'], 'https://example.com/meta/name=twitter:image:src')
        self.assertEqual(parsed.metadata['twitter']['site'], 'meta.name=twitter:site')
        self.assertEqual(parsed.metadata['twitter']['title'], 'meta.name=twitter:title')
        self.assertEqual(parsed.metadata['twitter']['url'], 'https://example.com/meta/name=twitter:url')
        self.assertEqual(parsed.metadata['twitter']['data'], 'meta.name=twitter:data||value')
        self.assertNotIn('label', parsed.metadata['twitter'])
        self.assertEqual(parsed.is_opengraph_minimum(), True)

    def test_html_urls(self):
        """this tests simple.html to have certain fields"""
        html = self._MakeOne('simple.html')
        parsed = metadata_parser.MetadataParser(url=None, html=html)
        # by default we do og_first
        self.assertEqual(parsed.get_discrete_url(), 'https://www.example.com/meta/property=og:url')
        self.assertEqual(parsed.get_discrete_url(canonical_first=True, og_first=False), 'http://example.com/meta/rel=canonical')
        self.assertEqual(parsed.get_url_opengraph(), 'https://www.example.com/meta/property=og:url')
        self.assertEqual(parsed.get_url_canonical(), 'http://example.com/meta/rel=canonical')

    def test_encoding_fallback(self):
        """this tests simple.html to have certain fields"""
        html = """<html><head></head><body>body</body></html>"""
        parsed = metadata_parser.MetadataParser(url=None, html=html)
        self.assertEqual(parsed.response.encoding, 'ISO-8859-1')

    def test_encoding_declared(self):
        html = """<html><head><meta charset="UTF-8"></head><body>body</body></html>"""
        parsed = metadata_parser.MetadataParser(url=None, html=html)
        self.assertEqual(parsed.response.encoding, 'UTF-8')

    def test_complex_html(self):
        """
        this tests duplicates.html to have certain fields

        this also ensures some legacy behavior is supported

        such as calling both:
            * `parsed.parsed_result.get_metadatas`
            * `parsed.get_metadatas`
        """
        html = self._MakeOne('duplicates.html')
        parsed = metadata_parser.MetadataParser(url=None, html=html)

        # this is just a property and should be the same object
        self.assertIs(parsed.metadata, parsed.parsed_result.metadata)

        # we should be tracking the verison now
        self.assertIn('_v', parsed.metadata)

        # it should be the same version
        self.assertEqual(parsed.metadata_version, metadata_parser.ParsedResult._version)
        self.assertEqual(parsed.parsed_result.metadata_version, metadata_parser.ParsedResult._version)

        # -----
        # this is a duplicate element and should be stored in the metadata dict as a list
        _citation_authors = ['citation_author:1', 'citation_author:2', 'citation_author:3', ]
        # these should be lists
        self.assertEqual(parsed.metadata['meta']['citation_author'], _citation_authors)
        self.assertEqual(parsed.parsed_result.get_metadatas('citation_author', ['meta', ]), _citation_authors)
        self.assertEqual(parsed.get_metadatas('citation_author', ['meta', ]), _citation_authors)
        # this is a string
        self.assertEqual(parsed.parsed_result.get_metadata('citation_author', ['meta', ]), _citation_authors[0])
        self.assertEqual(parsed.get_metadata('citation_author', ['meta', ]), _citation_authors[0])

        _meta_authors = ['meta.author:1', 'meta.author:2', ]
        # these should be lists
        self.assertEqual(parsed.metadata['meta']['author'], _meta_authors)
        self.assertEqual(parsed.parsed_result.get_metadatas('author', ['meta', ]), _meta_authors)
        self.assertEqual(parsed.get_metadatas('author', ['meta', ]), _meta_authors)
        # this is a string
        self.assertEqual(parsed.parsed_result.get_metadata('author', ['meta', ]), _meta_authors[0])
        self.assertEqual(parsed.get_metadata('author', ['meta', ]), _meta_authors[0])

        _meta_kws= ['meta.keywords:1', 'meta.keywords:2', ]
        # these should be lists
        self.assertEqual(parsed.metadata['meta']['keywords'], _meta_kws)
        self.assertEqual(parsed.parsed_result.get_metadatas('keywords', ['meta', ]), _meta_kws)
        self.assertEqual(parsed.get_metadatas('keywords', ['meta', ]), _meta_kws)
        # this is a string
        self.assertEqual(parsed.parsed_result.get_metadata('keywords', ['meta', ]), _meta_kws[0])
        self.assertEqual(parsed.get_metadata('keywords', ['meta', ]), _meta_kws[0])

        # -----
        # this is a single element and should be stored in the metadata dict as a string
        _description = 'meta.description'

        # these should be lists
        self.assertEqual(parsed.parsed_result.get_metadatas('description', ['meta', ]), [_description, ])
        self.assertEqual(parsed.get_metadatas('description', ['meta', ]), [_description, ])

        # this is a string
        self.assertEqual(parsed.metadata['meta']['description'], _description)
        self.assertEqual(parsed.parsed_result.get_metadata('description', ['meta', ]), _description)
        self.assertEqual(parsed.get_metadata('description', ['meta', ]), _description)

        # -----
        # dc creator has a language variant
        #  'dc': {'Creator': [{'content': 'Plato'},
        #                     {'content': 'Platon', 'lang': 'fr'}],

        self.assertIn('Creator', parsed.metadata['dc'])
        dc_creator = parsed.metadata['dc']['Creator']
        # so this should be a list
        self.assertIs(type(dc_creator), list)
        # with a length of 2
        self.assertEqual(len(dc_creator), 2)
        self.assertIs(type(dc_creator[0]), dict)
        self.assertIs(type(dc_creator[1]), dict)
        self.assertIn('content', dc_creator[0])
        self.assertEqual(dc_creator[0]['content'], 'Plato')
        self.assertIn('content', dc_creator[1])
        self.assertEqual(dc_creator[1]['content'], 'Platon')
        self.assertIn('lang', dc_creator[1])
        self.assertEqual(dc_creator[1]['lang'], 'fr')

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
        dcSubjectsExpected = [{'content': 'heart attack'},
                              {'content': 'Myocardial Infarction; Pericardial Effusion',
                               'scheme': 'MESH'},
                              {'content': 'vietnam war'},
                              {'content': 'Vietnamese Conflict, 1961-1975',
                               'scheme': 'LCSH'},
                              {'content': 'Friendship'},
                              {'content': '158.25', 'scheme': 'ddc'},
                              ]
        self.assertIn('Subject', parsed.metadata['dc'])
        dc_subject = parsed.metadata['dc']['Subject']
        self.assertIs(type(dc_subject), list)
        self.assertEqual(len(dc_subject), len(dcSubjectsExpected))
        for (idx, _expected) in enumerate(dc_subject):
            self.assertIs(type(dc_subject[idx]), dict)
            self.assertEqual(len(dc_subject[idx].keys()), len(dcSubjectsExpected[idx].keys()))
            self.assertEqual(sorted(dc_subject[idx].keys()), sorted(dcSubjectsExpected[idx].keys()))
            for _key in dc_subject[idx].keys():
                self.assertEqual(dc_subject[idx][_key], dcSubjectsExpected[idx][_key])

        # -----
        # dc TestMixedCandidates1
        # handle the ordering of results
        # the raw info tested is the same as the above Subject test...
        dcTestMixedCandidates1aExpected = {'content': 'Friendship'}
        self.assertIn('TestMixedCandidates1a', parsed.metadata['dc'])
        dc_mixed_candidates = parsed.metadata['dc']['TestMixedCandidates1a']
        self.assertIs(type(dc_mixed_candidates), dict)
        self.assertEqual(len(dc_mixed_candidates.keys()), len(dcTestMixedCandidates1aExpected.keys()))
        self.assertEqual(sorted(dc_mixed_candidates.keys()), sorted(dcTestMixedCandidates1aExpected.keys()))
        for _key in dc_mixed_candidates.keys():
            self.assertEqual(dc_mixed_candidates[_key], dcTestMixedCandidates1aExpected[_key])
        # but we need to test get_metadata and get_metadatas
        self.assertEqual(parsed.get_metadata('TestMixedCandidates1a', strategy='dc'), 'Friendship')
        self.assertEqual(parsed.get_metadatas('TestMixedCandidates1a', strategy='dc'), [dcTestMixedCandidates1aExpected, ])
        self.assertEqual(parsed.get_metadata('TestMixedCandidates1a', strategy='dc', encoder=encoder_capitalizer), 'FRIENDSHIP')
        self.assertEqual(parsed.get_metadatas('TestMixedCandidates1a', strategy='dc', encoder=encoder_capitalizer), [{'CONTENT': 'FRIENDSHIP'}])

        # 1b
        dcTestMixedCandidates1bExpected = {'content': '158.25', 'scheme': 'ddc'}
        self.assertIn('TestMixedCandidates1b', parsed.metadata['dc'])
        dc_mixed_candidates = parsed.metadata['dc']['TestMixedCandidates1b']
        self.assertIs(type(dc_mixed_candidates), dict)
        self.assertEqual(len(dc_mixed_candidates.keys()), len(dcTestMixedCandidates1bExpected.keys()))
        self.assertEqual(sorted(dc_mixed_candidates.keys()), sorted(dcTestMixedCandidates1bExpected.keys()))
        for _key in dc_mixed_candidates.keys():
            self.assertEqual(dc_mixed_candidates[_key], dcTestMixedCandidates1bExpected[_key])
        # but we need to test get_metadata and get_metadatas
        self.assertEqual(parsed.get_metadata('TestMixedCandidates1b', strategy='dc'), '158.25')
        self.assertEqual(parsed.get_metadatas('TestMixedCandidates1b', strategy='dc'), [dcTestMixedCandidates1bExpected, ])
        self.assertEqual(parsed.get_metadata('TestMixedCandidates1b', strategy='dc', encoder=encoder_capitalizer), '158.25')
        self.assertEqual(parsed.get_metadatas('TestMixedCandidates1b', strategy='dc', encoder=encoder_capitalizer), [{'CONTENT': '158.25', 'SCHEME': 'DDC'}])

        # -----
        # dc TestMixedCandidates2
        # handle the ordering of results
        # the raw info tested is the same as the above Subject test...
        dcTestMixedCandidates2aExpected = [{'content': '158.25', 'scheme': 'ddc'},
                                           {'content': 'Friendship'},
                                           ]
        self.assertIn('TestMixedCandidates2a', parsed.metadata['dc'])
        dc_mixed_candidates = parsed.metadata['dc']['TestMixedCandidates2a']
        self.assertIs(type(dc_mixed_candidates), list)
        self.assertEqual(len(dc_mixed_candidates), len(dcTestMixedCandidates2aExpected))
        for (idx, _expected) in enumerate(dc_mixed_candidates):
            self.assertIs(type(dc_mixed_candidates[idx]), dict)
            self.assertEqual(len(dc_mixed_candidates[idx].keys()), len(dcTestMixedCandidates2aExpected[idx].keys()))
            self.assertEqual(sorted(dc_mixed_candidates[idx].keys()), sorted(dcTestMixedCandidates2aExpected[idx].keys()))
            for _key in dc_mixed_candidates[idx].keys():
                self.assertEqual(dc_mixed_candidates[idx][_key], dcTestMixedCandidates2aExpected[idx][_key])
        # but we need to test get_metadata and get_metadatas

        self.assertEqual(parsed.get_metadata('TestMixedCandidates2a', strategy='dc'), 'Friendship')
        self.assertEqual(parsed.get_metadatas('TestMixedCandidates2a', strategy='dc'), dcTestMixedCandidates2aExpected)
        self.assertEqual(parsed.get_metadata('TestMixedCandidates2a', strategy='dc', encoder=encoder_capitalizer), 'FRIENDSHIP')
        self.assertEqual(parsed.get_metadatas('TestMixedCandidates2a', strategy='dc', encoder=encoder_capitalizer), [{'CONTENT': '158.25', 'SCHEME': 'DDC'}, {'CONTENT': 'FRIENDSHIP'}])

        # 2b
        dcTestMixedCandidates2bExpected = [{'content': 'Friendship'},
                                           {'content': '158.25', 'scheme': 'ddc'},
                                           ]
        self.assertIn('TestMixedCandidates2b', parsed.metadata['dc'])
        dc_mixed_candidates = parsed.metadata['dc']['TestMixedCandidates2b']
        self.assertIs(type(dc_mixed_candidates), list)
        self.assertEqual(len(dc_mixed_candidates), len(dcTestMixedCandidates2bExpected))
        for (idx, _expected) in enumerate(dc_mixed_candidates):
            self.assertIs(type(dc_mixed_candidates[idx]), dict)
            self.assertEqual(len(dc_mixed_candidates[idx].keys()), len(dcTestMixedCandidates2bExpected[idx].keys()))
            self.assertEqual(sorted(dc_mixed_candidates[idx].keys()), sorted(dcTestMixedCandidates2bExpected[idx].keys()))
            for _key in dc_mixed_candidates[idx].keys():
                self.assertEqual(dc_mixed_candidates[idx][_key], dcTestMixedCandidates2bExpected[idx][_key])
        # but we need to test get_metadata and get_metadatas
        self.assertEqual(parsed.get_metadata('TestMixedCandidates2b', strategy='dc'), 'Friendship')
        self.assertEqual(parsed.get_metadatas('TestMixedCandidates2b', strategy='dc'), dcTestMixedCandidates2bExpected)
        self.assertEqual(parsed.get_metadata('TestMixedCandidates2b', strategy='dc', encoder=encoder_capitalizer), 'FRIENDSHIP')
        self.assertEqual(parsed.get_metadatas('TestMixedCandidates2b', strategy='dc', encoder=encoder_capitalizer), [{'CONTENT': 'FRIENDSHIP'}, {'CONTENT': '158.25', 'SCHEME': 'DDC'}])

        # ok, mixedfield tests:
        # TestMixedField0
        self.assertEqual(parsed.get_metadata('TestMixedField0', strategy='dc'), None)
        self.assertEqual(parsed.get_metadata('TestMixedField0', strategy='meta'), 'meta:TestMixedField0')
        self.assertEqual(parsed.get_metadata('TestMixedField0', strategy='all'), {'meta': 'meta:TestMixedField0', })
        self.assertEqual(parsed.get_metadata('TestMixedField0', strategy='dc', encoder=encoder_capitalizer), None)
        self.assertEqual(parsed.get_metadata('TestMixedField0', strategy='meta', encoder=encoder_capitalizer), 'META:TESTMIXEDFIELD0')
        self.assertEqual(parsed.get_metadata('TestMixedField0', strategy='all', encoder=encoder_capitalizer), {'meta': 'META:TESTMIXEDFIELD0', })
        self.assertEqual(parsed.get_metadatas('TestMixedField0', strategy='dc'), None)
        self.assertEqual(parsed.get_metadatas('TestMixedField0', strategy='meta'), ['meta:TestMixedField0', ])
        self.assertEqual(parsed.get_metadatas('TestMixedField0', strategy='all'), {'meta': ['meta:TestMixedField0',] })
        self.assertEqual(parsed.get_metadatas('TestMixedField0', strategy='dc', encoder=encoder_capitalizer), None)
        self.assertEqual(parsed.get_metadatas('TestMixedField0', strategy='meta', encoder=encoder_capitalizer), ['META:TESTMIXEDFIELD0', ])
        self.assertEqual(parsed.get_metadatas('TestMixedField0', strategy='all', encoder=encoder_capitalizer), {'meta': ['META:TESTMIXEDFIELD0', ], })

        # TestMixedField1
        self.assertEqual(parsed.get_metadata('TestMixedField1', strategy='dc'), 'dc:TestMixedField1')
        self.assertEqual(parsed.get_metadata('TestMixedField1', strategy='meta'), 'meta:TestMixedField1')
        self.assertEqual(parsed.get_metadata('TestMixedField1', strategy='all'), {'meta': 'meta:TestMixedField1',
                                                                                  'dc': 'dc:TestMixedField1',
                                                                                  })
        self.assertEqual(parsed.get_metadata('TestMixedField1', strategy='dc', encoder=encoder_capitalizer), 'DC:TESTMIXEDFIELD1')
        self.assertEqual(parsed.get_metadata('TestMixedField1', strategy='meta', encoder=encoder_capitalizer), 'META:TESTMIXEDFIELD1')
        self.assertEqual(parsed.get_metadata('TestMixedField1', strategy='all', encoder=encoder_capitalizer), {'meta': 'META:TESTMIXEDFIELD1',
                                                                                                               'dc': 'DC:TESTMIXEDFIELD1'
                                                                                                               })
        self.assertEqual(parsed.get_metadatas('TestMixedField1', strategy='dc'), [{'content': 'dc:TestMixedField1'}, ])
        self.assertEqual(parsed.get_metadatas('TestMixedField1', strategy='meta'), ['meta:TestMixedField1', ])
        self.assertEqual(parsed.get_metadatas('TestMixedField1', strategy='all'), {'meta': ['meta:TestMixedField1', ],
                                                                                   'dc': [{'content': 'dc:TestMixedField1',}],
                                                                                   })
        self.assertEqual(parsed.get_metadatas('TestMixedField1', strategy='dc', encoder=encoder_capitalizer), [{'CONTENT': 'DC:TESTMIXEDFIELD1'}, ])
        self.assertEqual(parsed.get_metadatas('TestMixedField1', strategy='meta', encoder=encoder_capitalizer), ['META:TESTMIXEDFIELD1', ])
        self.assertEqual(parsed.get_metadatas('TestMixedField1', strategy='all', encoder=encoder_capitalizer), {'meta': ['META:TESTMIXEDFIELD1', ],
                                                                                                                'dc': [{'CONTENT': 'DC:TESTMIXEDFIELD1',},
                                                                                                                ]})
        # TestMixedField2
        self.assertEqual(parsed.get_metadata('TestMixedField2', strategy='dc'), 'dc:TestMixedField2')
        self.assertEqual(parsed.get_metadata('TestMixedField2', strategy='meta'), 'meta:TestMixedField2')
        self.assertEqual(parsed.get_metadata('TestMixedField2', strategy='all'), {'meta': 'meta:TestMixedField2',
                                                                                  'dc': 'dc:TestMixedField2',
                                                                                  })
        self.assertEqual(parsed.get_metadata('TestMixedField2', strategy='dc', encoder=encoder_capitalizer), 'DC:TESTMIXEDFIELD2')
        self.assertEqual(parsed.get_metadata('TestMixedField2', strategy='meta', encoder=encoder_capitalizer), 'META:TESTMIXEDFIELD2')
        self.assertEqual(parsed.get_metadata('TestMixedField2', strategy='all', encoder=encoder_capitalizer), {'meta': 'META:TESTMIXEDFIELD2',
                                                                                                               'dc': 'DC:TESTMIXEDFIELD2',
                                                                                                               })
        self.assertEqual(parsed.get_metadatas('TestMixedField2', strategy='dc'), [{'content': 'dc:TestMixedField2'},
                                                                                  {'content': 'dc:TestMixedField2.ddc', 'scheme': 'ddc'}
                                                                                  ])
        self.assertEqual(parsed.get_metadatas('TestMixedField2', strategy='meta'), ['meta:TestMixedField2', ])
        self.assertEqual(parsed.get_metadatas('TestMixedField2', strategy='all'), {'meta': ['meta:TestMixedField2', ],
                                                                                   'dc': [{'content': 'dc:TestMixedField2'},
                                                                                          {'content': 'dc:TestMixedField2.ddc', 'scheme': 'ddc'},
                                                                                          ],
                                                                                   })
        self.assertEqual(parsed.get_metadatas('TestMixedField2', strategy='dc', encoder=encoder_capitalizer), [{'CONTENT': 'DC:TESTMIXEDFIELD2'},
                                                                                                               {'CONTENT': 'DC:TESTMIXEDFIELD2.DDC', 'SCHEME': 'DDC'},
                                                                                                               ])
        self.assertEqual(parsed.get_metadatas('TestMixedField2', strategy='meta', encoder=encoder_capitalizer), ['META:TESTMIXEDFIELD2', ])
        self.assertEqual(parsed.get_metadatas('TestMixedField2', strategy='all', encoder=encoder_capitalizer), {'meta': ['META:TESTMIXEDFIELD2', ],
                                                                                                                'dc': [{'CONTENT': 'DC:TESTMIXEDFIELD2', },
                                                                                                                       {'CONTENT': 'DC:TESTMIXEDFIELD2.DDC', 'SCHEME': 'DDC'},
                                                                                                                       ]
                                                                                                                })

        # TestMixedField3
        self.assertEqual(parsed.get_metadata('TestMixedField3', strategy='dc'), 'dc:TestMixedField3')
        self.assertEqual(parsed.get_metadata('TestMixedField3', strategy='meta'), 'meta:TestMixedField3')
        self.assertEqual(parsed.get_metadata('TestMixedField3', strategy='all'), {'meta': 'meta:TestMixedField3',
                                                                                  'dc': 'dc:TestMixedField3',
                                                                                  })
        self.assertEqual(parsed.get_metadata('TestMixedField3', strategy='dc', encoder=encoder_capitalizer), 'DC:TESTMIXEDFIELD3')
        self.assertEqual(parsed.get_metadata('TestMixedField3', strategy='meta', encoder=encoder_capitalizer), 'META:TESTMIXEDFIELD3')
        self.assertEqual(parsed.get_metadata('TestMixedField3', strategy='all', encoder=encoder_capitalizer), {'meta': 'META:TESTMIXEDFIELD3',
                                                                                                               'dc': 'DC:TESTMIXEDFIELD3'
                                                                                                               })
        self.assertEqual(parsed.get_metadatas('TestMixedField3', strategy='dc'), [{'content': 'dc:TestMixedField3'}, ])
        self.assertEqual(parsed.get_metadatas('TestMixedField3', strategy='meta'), ['meta:TestMixedField3', ])
        self.assertEqual(parsed.get_metadatas('TestMixedField3', strategy='all'), {'meta': ['meta:TestMixedField3', ],
                                                                                   'dc': [{'content': 'dc:TestMixedField3',}],
                                                                                   })
        self.assertEqual(parsed.get_metadatas('TestMixedField3', strategy='dc', encoder=encoder_capitalizer), [{'CONTENT': 'DC:TESTMIXEDFIELD3'}, ])
        self.assertEqual(parsed.get_metadatas('TestMixedField3', strategy='meta', encoder=encoder_capitalizer), ['META:TESTMIXEDFIELD3', ])
        self.assertEqual(parsed.get_metadatas('TestMixedField3', strategy='all', encoder=encoder_capitalizer), {'meta': ['META:TESTMIXEDFIELD3', ],
                                                                                                                'dc': [{'CONTENT': 'DC:TESTMIXEDFIELD3',},
                                                                                                                ]})

    def test_malformed_twitter(self):
        """
        this tests simple.html to have certain fields
        python -munittest tests.document_parsing.TestDocumentParsing.test_malformed_twitter
        """
        html = self._MakeOne('simple.html')

        # the default behavior is to not support malformed
        # that means we should consult 'value' for data and 'label'
        # in `simple.html`, "label" (incorrectly) uses "content" and "data" uses "label"
        parsed = metadata_parser.MetadataParser(url=None, html=html)
        self.assertEqual(parsed.metadata['twitter']['data'], 'meta.name=twitter:data||value')
        self.assertNotIn('label', parsed.metadata['twitter'])
        self.assertNotIn('invalid', parsed.metadata['twitter'])

        # now with `support_malformed` support we will load the label!
        parsed2 = metadata_parser.MetadataParser(url=None, html=html, support_malformed=True)
        self.assertEqual(parsed2.metadata['twitter']['data'], 'meta.name=twitter:data||value')
        self.assertEqual(parsed2.metadata['twitter']['label'], 'meta.name=twitter:label||content')
        self.assertEqual(parsed2.metadata['twitter']['invalid'], 'meta.name=twitter:invalid')

        # try it with dupes...
        html_dupes = self._MakeOne('duplicates.html')
        parsed_dupe = metadata_parser.MetadataParser(url=None, html=html_dupes)
        # two items for each of data/label, but label is empty strings
        self.assertEqual(parsed_dupe.metadata['twitter']['data'], ['meta.name=twitter:data||value,1',
                                                                   'meta.name=twitter:data||value,2',
                                                                   ])
        self.assertNotIn('label', parsed.metadata['twitter'])

        # everyone is happy when metadata is malformed!
        parsed_dupe = metadata_parser.MetadataParser(url=None, html=html_dupes, support_malformed=True)
        self.assertEqual(parsed_dupe.metadata['twitter']['data'], ['meta.name=twitter:data||value,1',
                                                                   'meta.name=twitter:data||value,2',
                                                                   ])
        self.assertEqual(parsed_dupe.metadata['twitter']['label'], ['meta.name=twitter:label||content,1',
                                                                    'meta.name=twitter:label||content,2',
                                                                    ])



