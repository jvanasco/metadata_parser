MetadataParser is a python module for pulling metadata out of web documents.

It requires BeautifulSoup , and was largely based on Erik River's opengraph module ( https://github.com/erikriver/opengraph ).

I needed something more aggressive than Erik's module , so had to fork.


Installation
=============

pip install metadata_parser


Installation Recommendation
===========================

I strongly suggest you use the `requests` library version 2.4.3 or newer

This is not required, but it is better.  On earlier versions it is possible to have an uncaught DecodeError exception when there is an underlying redirect/404.  Recent fixes to `requests` improve redirect handling, urllib3 and urllib3 errors.


Features
=============

* it pulls as much metadata out of a document as possible
* you can set a 'strategy' for finding metadata ( ie, only accept opengraph or page attributes )
* lightweight BUT FUNCTIONAL url validation
* logging is verbose, but nested under `__debug__` statements, so it is compiled away when PYTHONOPTIMIZE is set

Notes
=============
1. This requires BeautifulSoup 4.
2. For speed, it will instantiate a BeautifulSoup parser with lxml , and fall back to 'none' (the internal pure python) if it can't load lxml
3. URL Validation is not RFC compliant, but tries to be "Real World" compliant

* It is HIGHLY recommended that you install lxml for usage.  It is considerably faster.  Considerably faster. *

You should also use a very recent version of lxml.  I've had problems with segfaults on some versions < 2.3.x ; i would suggest using the most recent 3.x if possible.

The default 'strategy' is to look in this order:

    og,dc,meta,page
    og = OpenGraph
    dc = DublinCore
    meta = metadata
    page = page elements

You can specify a strategy as a comma-separated list of the above.

The only 2 page elements currently supported are:

    <title>VALUE</title> -> metadata['page']['title']
    <link rel="canonical" href="VALUE"> -> metadata['page']['link']

'metadata' elements are supported by `name` and `property`.

The MetadataParser object also wraps some convenience functions , which can be used otherwise , that are designed to turn alleged urls into well formed urls.

For example, you may pull a page:

    http://www.example.com/path/to/file.html

and that file indicates a canonical url which is simple "/file.html".

This package will try to 'remount' the canonical url to the absolute url of "http://www.example.com/file.html" .  It will return None if the end result is not a valid url.

This all happens under-the-hood, and is honestly really useful when dealing with indexers and spiders.



URL Validation
=================

"Real World" URL validation is enabled by default.  This is not RFC compliant.

There are a few gaps in the RFCs that allow for "odd behavior".  Just about any use-case for this package will desire/expect rules that parse URLs "in the wild", not theoretical.

The differences:

* If an entirely numeric ip address is encountered, it is assumed to be a dot-notation IPV4 and it is checked to have the right amount of valid octets.
    The default behavior is to invalidate these hosts:
        http://256.256.256.256
        http://999.999.999.999.999
    According to RFCs those are valid hostnames that would fail as "IP Addresses" but pass as "Domain Names".  However in the real world, one would never encounter domain names like those.

* The only non-domain hostname that is allowed, is "localhost"
    The default behavior is to invalidate  these hosts :
        http://example
        http://examplecom
    Those are considered to be valid hosts, and might exist on a local network or custom hosts file.  However, they are not part of the public internet.

Although this behavior breaks RFCs, it greatly reduces the number of "False Positives" generated when analyzing internet pages.  If you want to include bad data, you can submit a kwarg to `MetadataParser.__init__`


Handling Bad URLs and Encoded URIs
==================================

This library tries to safeguard against a few common situations.

# Encoded URIs and relative urls

Most website publishers will define an image as a URL

    <meta property="og:image" content="http://example.com/image.jpg" />

Some will define an image as an encoded URI

    <meta property="og:image" content="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNM+Q8AAc0BZX6f84gAAAAASUVORK5CYII=" />

By default, the `get_metadata_link()` method can be used to ensure a valid link is extracted from the metadata payload

    >>> import metadata_parser
    >>> page = metadata_parser.MetadataParser(url="http://www.example.com")
    >>> print page.get_metadata_link('image')

This method accepts a kwarg `allow_encoded_uri` (default False) which will return the image without further processing:

    >>> print page.get_metadata_link('image', allow_encoded_uri=True)
    
Similarly, if a url is local...

    <meta property="og:image" content="/image.jpg" />


The `get_metadata_link` method will automatically upgrade it onto the domain:

    >>> print page.get_metadata_link('image')
    http://example.com/image.jpg



# Poorly Constructed Canonical URLs

Many website publishers implement canonical URLs incorrectly.  This package tries to fix that.

By default `MetadataParser` is constructed with `require_public_netloc=True` and `allow_localhosts=True`.

This will require somewhat valid 'public' network locations in the url.  

For example, these will all be valid URLs:

    http://example.com
    http://1.2.3.4
    http://localhost
    http://127.0.0.1
    http://0.0.0.0

If these known 'localhost' urls are not wanted, they can be filtered out with `allow_localhosts=False`

    http://localhost
    http://127.0.0.1
    http://0.0.0.0

There are two convenience methods that can be used to get a canonical url or calculate the effective url:

* MetadataParser.get_discrete_url
* MetadataParser.get_metadata_link

These both accept an argument `require_public_global`, which defaults to `True`.

Assuming we have the following content on the url `http://example.com/path/to/foo`

    <link rel="canonical" href="http://localhost:8000/alt-path/to/foo">

By default, versions 0.9.0 and later will detect 'localhost:8000' as an improper canonical url, and remount the local part "/alt-path/to/foo" onto the domain that served the file.  The vast majority of times this 'behavior' has been encountered, this is the intended canonical.

    print page.get_discrete_url()
    >>> http://example.com/alt-path/to/foo

In contrast, versions 0.8.3 and earlier will not catch this situation.

    print page.get_discrete_url()
    >>> http://localhost:8000/alt-path/to/foo

In order to preserve the earlier behavior, just submit `require_public_global=False`

    print page.get_discrete_url(require_public_global=False)
    >>> http://localhost:8000/alt-path/to/foo

WARNING
=============

1.0 will be a complete API overhaul.  pin your releases to avoid sadness.


Usage
==============

**From an URL**

    >>> import metadata_parser
    >>> page = metadata_parser.MetadataParser(url="http://www.example.com")
    >>> print page.metadata
    >>> print page.get_metadata('title')
    >>> print page.get_metadata('title', strategy=['og',])
    >>> print page.get_metadata('title', strategy=['page', 'og', 'dc',])

**From HTML**

    >>> HTML = """<here>"""
    >>> page = metadata_parser.MetadataParser(html=HTML)
    >>> print page.metadata
    >>> print page.get_metadata('title')
    >>> print page.get_metadata('title', strategy=['og',])
    >>> print page.get_metadata('title', strategy=['page', 'og', 'dc',])
