import metadata_parser

import unittest

doc_base = """<html><head>%(head)s</head><body></body></html>"""

docs = {
    'good-canonical-absolute' : {
        'url-real' : """http://example.com""",
        'head' : {
            'url-canonical' : """http://example.com/canonical.html""",
            'url-og' : None ,
        },
        'expected' : {
            'get_discrete_url()' : 'http://example.com/canonical.html',
        },
    },
    'good-og-absolute' : {
        'url-real' : """http://example.com""",
        'head' : {
            'url-canonical' : None ,
            'url-og' : """http://example.com/og.html""",
        },
        'expected' : {
            'get_discrete_url()' : 'http://example.com/og.html',
        },
    },
    'good-canonical-relative' : {
        'url-real' : """http://example.com""",
        'head' : {
            'url-canonical' : """canonical.html""",
            'url-og' : None ,
        },
        'expected' : {
            'get_discrete_url()' : 'http://example.com/canonical.html',
        },
    },
    'good-canonical-relative_alt' : {
        'url-real' : """http://example.com""",
        'head' : {
            'url-canonical' : """/canonical.html""",
            'url-og' : None ,
        },
        'expected' : {
            'get_discrete_url()' : 'http://example.com/canonical.html',
        },
    },
    'good-og-relative_alt' : {
        'url-real' : """http://example.com""",
        'head' : {
            'url-canonical' : None ,
            'url-og' : """/og.html""",
        },
        'expected' : {
            'get_discrete_url()' : 'http://example.com/og.html',
        },
    },


    'bad-canonical' : {
        'url-real' : """http://example.com/one-two-three.html""",
        'head' : {
            'url-canonical' : """...""",
            'url-og' : None ,
        },
        'expected' : {
            'get_discrete_url()' : 'http://example.com/one-two-three.html',
        },
    },
    'bad-canonical2' : {
        'url-real' : """http://example.com/one-two-three.html""",
        'head' : {
            'url-canonical' : """http://""",
            'url-og' : None ,
        },
        'expected' : {
            'get_discrete_url()' : 'http://example.com/one-two-three.html',
        },
    },
    'bad-og' : {
        'url-real' : """http://example.com/one-two-three.html""",
        'head' : {
            'url-canonical' : None ,
            'url-og' :  """...""",
        },
        'expected' : {
            'get_discrete_url()' : 'http://example.com/one-two-three.html',
        },
    },


}

## setup the test_docs with html bodies
for test in docs.keys():
    head = ''
    if docs[test]['head']['url-og'] is not None :
        head += """<meta property="og:url" content="%s"/>""" % docs[test]['head']['url-og']
    if docs[test]['head']['url-canonical'] is not None :
        head += """<link rel="canonical" href="%s" />""" % docs[test]['head']['url-canonical']
    custom_vars = { 'head': head }
    docs[test]['doc'] = doc_base % custom_vars


def _docs_test( test_names ):
    errors = []
    for test in test_names:
        url = docs[test]['url-real']
        url_expected = docs[test]['expected']['get_discrete_url()']
        parsed = metadata_parser.MetadataParser( url=url , html=docs[test]['doc'] )
        url_retrieved = parsed.get_discrete_url()
        if url_retrieved != url_expected :
            errors.append( [test, url_expected, url_retrieved, ] )
    return errors




class TestHtmlDocument( unittest.TestCase ):
    """
        python -m unittest tests.html_documents.TestHtmlDocument.test_get_discrete_url__good_relative
        python -m unittest tests.html_documents.TestHtmlDocument.test_get_discrete_url__good_absolute
        python -m unittest tests.html_documents.TestHtmlDocument.test_get_discrete_url__bad
    """

    def test_get_discrete_url__good_relative(self):
        errors = _docs_test( ['good-canonical-relative', 'good-canonical-relative_alt', 'good-og-relative_alt', ] )
        if errors:
            raise ValueError(errors)


    def test_get_discrete_url__good_absolute(self):
        errors = _docs_test( ['good-canonical-absolute', 'good-og-absolute', ] )
        if errors:
            raise ValueError(errors)


    def test_get_discrete_url__bad(self):
        errors = _docs_test( ['bad-canonical', 'bad-canonical2', 'bad-og', ] )
        if errors:
            raise ValueError(errors)



