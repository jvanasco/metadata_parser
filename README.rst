MetadataParser
==============

.. |build_status| image:: https://github.com/jvanasco/metadata_parser/workflows/Python%20package/badge.svg

Build Status: |build_status|

MetadataParser is a Python module for pulling metadata out of web documents.

It requires `BeautifulSoup` for parsing. `Requests` is required for installation
at this time, but not for operation. Additional functionality is automatically
enabled if the `tldextract` project is installed, but can be disabled by
setting an environment variable.

This project has been used in production for many years, and has successfully
parsed billions of documents.


Versioning, Pinning, and Support
================================

This project is using a Semantic Versioning release schedule,
with a {MAJOR}.{MINOR}.{PATCH} format.

Users are advised to pin their installations to "metadata_parser<{MINOR +1}"

For example:

* if the current release is: `0.10.6`
* the advised pin is:  `metadata_parser<0.11`

PATCH releases will usually be bug fixes and new features that support backwards compatibility with Public Methods.  Private Methods are not guaranteed to be
backwards compatible.

MINOR releases are triggered when there is a breaking change to Public Methods.
Once a new MINOR release is triggered, first-party support for the previous MINOR
release is EOL (end of life). PRs for previous releases are welcome, but giving
them proper attention is not guaranteed.

The current MAJOR release is `0`.
A `1` MAJOR release is planned, and will have an entirely different structure and API.

Future deprecations will raise warnings.

By populating the following environment variable, future deprecations will raise exceptions:
    export METADATA_PARSER_FUTURE=1

Installation
=============

pip install metadata_parser


Installation Recommendation
===========================

The ``requests`` library version 2.4.3 or newer is strongly recommended.

This is not required, but it is better.  On earlier versions it is possible to
have an uncaught DecodeError exception when there is an underlying redirect/404.
Recent fixes to ``requests`` improve redirect handling, urllib3 and urllib3
errors.


Features
========

* ``metadata_parser`` pulls as much metadata out of a document as possible
* Developers can set a 'strategy' for finding metadata (i.e. only accept
  opengraph or page attributes)
* Lightweight but functional(!) url validation
* Verbose logging

Logging
=======

This file has extensive logging to help developers pinpoint problems.

* ``log.debug``
  This log level is mostly used to handle library maintenance and
  troubleshooting, aka "Library Debugging".  Library Debugging is verbose, but
  is nested under ``if __debug__:`` statements, so it is compiled away when
  PYTHONOPTIMIZE is set.
  Several sections of logic useful to developers will also emit logging
  statements at the ``debug`` level, regardless of PYTHONOPTIMIZE.

* ``log.info``
  Currently unused

* ``log.warning``
  Currently unused

* ``log.error``
  This log level is mostly used to alert developers of errors that were
  encountered during url fetching and document parsing, and often emits a log
  statement just before an Exception is raised. The log statements will contain
  at least the exception type, and may contain the active URL and additional
  debugging information, if any of that information is available.

* ``log.critical``
  Currently unused


It is STRONGLY recommended to keep Python's logging at ``debug``.


Optional Integrations
=====================

* ``tldextract``
  This package will attempt to use the package ``tldextract`` for advanced domain
  and hostname analysis. If ``tldextract`` is not found, a fallback is used.


Environment Variables
=====================

* ``METADATA_PARSER__DISABLE_TLDEXTRACT``
  Default: "0".
  If set to "1", the package will not attempt to load ``tldextract``.

* ``METADATA_PARSER__ENCODING_FALLBACK``
  Default: "ISO-8859-1"
  Used as the fallback when trying to decode a response.

*  ``METADATA_PARSER__DUMMY_URL``
   Used as the fallback URL when calculating url data.


Notes
=====

1. This package requires BeautifulSoup 4.
2. For speed, it will instantiate a BeautifulSoup parser with lxml, and
   fallback to 'none' (the internal pure Python) if it can't load lxml.
3. URL Validation is not RFC compliant, but tries to be "Real World" compliant.

It is HIGHLY recommended that you install lxml for usage.
lxml is considerably faster.
Considerably faster.

Developers should also use a very recent version of lxml.
segfaults have been reported on lxml versions < 2.3.x;
Using at least the most recent 3.x versions is strongly recommended

The default 'strategy' is to look in this order::

    og,dc,meta,page

Which stands for the following::

    og = OpenGraph
    dc = DublinCore
    meta = metadata
    page = page elements

Developers can specify a strategy as a comma-separated list of the above.

The only 2 page elements currently supported are::

    <title>VALUE</title> -> metadata['page']['title']
    <link rel="canonical" href="VALUE"> -> metadata['page']['link']

'metadata' elements are supported by ``name`` and ``property``.

The MetadataParser object also wraps some convenience functions, which can be
used otherwise , that are designed to turn alleged urls into well formed urls.

For example, you may pull a page::

    http://www.example.com/path/to/file.html

and that file indicates a canonical url which is simple "/file.html".

This package will try to 'remount' the canonical url to the absolute url of
"http://www.example.com/file.html".
Tt will return None if the end result is not a valid url.

This all happens under-the-hood, and is honestly really useful when dealing
with indexers and spiders.


URL Validation
==============

"Real World" URL validation is enabled by default.  This is not RFC compliant.

There are a few gaps in the RFCs that allow for "odd behavior".
Just about any use-case for this package will desire/expect rules that parse
URLs "in the wild", not theoretical.

The differences:

* If an entirely numeric ip address is encountered, it is assumed to be a
  dot-notation IPV4 and it is checked to have the right amount of valid octets.
  
  The default behavior is to invalidate these hosts::

        http://256.256.256.256
        http://999.999.999.999.999

  According to RFCs those are valid hostnames that would fail as "IP Addresses"
  but pass as "Domain Names".  However in the real world, one would never
  encounter domain names like those.

* The only non-domain hostname that is allowed, is "localhost"

  The default behavior is to invalidate these hosts ::

        http://example
        http://examplecom

  Those are considered to be valid hosts, and might exist on a local network or
  custom hosts file.  However, they are not part of the public internet.

Although this behavior breaks RFCs, it greatly reduces the number of
"False Positives" generated when analyzing internet pages. If you want to
include bad data, you can submit a kwarg to ``MetadataParser.__init__``


Handling Bad URLs and Encoded URIs
==================================

This library tries to safeguard against a few common situations.

Encoded URIs and relative urls
------------------------------

Most website publishers will define an image as a URL::

    <meta property="og:image" content="http://example.com/image.jpg" />

Some will define an image as an encoded URI::

    <meta property="og:image" content="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAQAAAC1HAwCAAAAC0lEQVR42mNM+Q8AAc0BZX6f84gAAAAASUVORK5CYII=" />

By default, the ``get_metadata_link()`` method can be used to ensure a valid link
is extracted from the metadata payload::

    >>> import metadata_parser
    >>> page = metadata_parser.MetadataParser(url="http://www.example.com")
    >>> print page.get_metadata_link('image')

This method accepts a kwarg ``allow_encoded_uri`` (default False) which will
return the image without further processing::

    >>> print page.get_metadata_link('image', allow_encoded_uri=True)

Similarly, if a url is local::

    <meta property="og:image" content="/image.jpg" />

The ``get_metadata_link`` method will automatically upgrade it onto the domain::

    >>> print page.get_metadata_link('image')
    http://example.com/image.jpg

Poorly Constructed Canonical URLs
---------------------------------

Many website publishers implement canonical URLs incorrectly.  This package
tries to fix that.

By default ``MetadataParser`` is constructed with ``require_public_netloc=True``
and ``allow_localhosts=True``.

This will require somewhat valid 'public' network locations in the url.

For example, these will all be valid URLs::

    http://example.com
    http://1.2.3.4
    http://localhost
    http://127.0.0.1
    http://0.0.0.0

If these known 'localhost' urls are not wanted, they can be filtered out with
``allow_localhosts=False``::

    http://localhost
    http://127.0.0.1
    http://0.0.0.0

There are two convenience methods that can be used to get a canonical url or
calculate the effective url::

* MetadataParser.get_discrete_url
* MetadataParser.get_metadata_link

These both accept an argument ``require_public_global``, which defaults to ``True``.

Assuming we have the following content on the url ``http://example.com/path/to/foo``::

    <link rel="canonical" href="http://localhost:8000/alt-path/to/foo">

By default, versions 0.9.0 and later will detect 'localhost:8000' as an
improper canonical url, and remount the local part "/alt-path/to/foo" onto the
domain that served the file.  The vast majority of times this 'behavior'
has been encountered, this is the intended canonical::

    print page.get_discrete_url()
    >>> http://example.com/alt-path/to/foo

In contrast, versions 0.8.3 and earlier will not catch this situation::

    print page.get_discrete_url()
    >>> http://localhost:8000/alt-path/to/foo

In order to preserve the earlier behavior, just submit ``require_public_global=False``::

    print page.get_discrete_url(require_public_global=False)
    >>> http://localhost:8000/alt-path/to/foo


Handling Bad Data
=================

Many CMS systems (and developers) create malformed content or incorrect
document identifiers.  When this happens, the BeautifulSoup parser will lose
data or move it into an unexpected place.

There are two arguments that can help you analyze this data:

* force_doctype::

    ``MetadataParser(..., force_doctype=True, ...)``

``force_doctype=True`` will try to replace the identified doctype with "html"
via regex.  This will often make the input data usable by BS4.

* search_head_only::

    ``MetadataParser(..., search_head_only=False, ...)``

``search_head_only=False`` will not limit the search path to the "<head>" element.
This will have a slight performance hit and will incorporate data from CMS/User
content, not just templates/Site-Operators.


WARNING
=============

1.0 will be a complete API overhaul.  pin your releases to avoid sadness.


Version 0.9.19 Breaking Changes
===============================

Issue #12 exposed some flaws in the existing package

1. ``MetadataParser.get_metadatas`` replaces ``MetadataParser.get_metadata``
----------------------------------------------------------------------------

Until version 0.9.19, the recommended way to get metadata was to use
``get_metadata`` which will either return a string (or None).

Starting with version 0.9.19, the recommended way to get metadata is to use
``get_metadatas`` which will always return a list (or None).

This change was made because the library incorrectly stored a single metadata
key value when there were duplicates.

2. The ``ParsedResult`` payload stores mixed content and tracks it's version
==--------------------------------------------------------------------------

Many users (including the maintainer) archive the parsed metadata. After
testing a variety of payloads with an all-list format and a mixed format
(string or list), a mixed format had a much smaller payload size with a
negligible performance hit. A new ``_v`` attribute tracks the payload version.
In the future, payloads without a ``_v`` attribute will be interpreted as the
pre-versioning format.

3. ``DublinCore`` payloads might be a dict
------------------------------------------

Tests were added to handle dublincore data. An extra attribute may be needed to
properly represent the payload, so always returning a dict with at least a
name+content (and possibly ``lang`` or ``scheme`` is the best approach.



Usage
=====

Until version ``0.9.19``, the recommended way to get metadata was to use
``get_metadata`` which will return a string (or None):

**From an URL**::

    >>> import metadata_parser
    >>> page = metadata_parser.MetadataParser(url="http://www.example.com")
    >>> print page.metadata
    >>> print page.get_metadatas('title')
    >>> print page.get_metadatas('title', strategy=['og',])
    >>> print page.get_metadatas('title', strategy=['page', 'og', 'dc',])

**From HTML**::

    >>> HTML = """<here>"""
    >>> page = metadata_parser.MetadataParser(html=HTML)
    >>> print page.metadata
    >>> print page.get_metadatas('title')
    >>> print page.get_metadatas('title', strategy=['og',])
    >>> print page.get_metadatas('title', strategy=['page', 'og', 'dc',])


Malformed Data
==============

It is very common to find malformed data. As of version ``0.9.20`` the following
methods should be used to allow malformed presentation::

    >>> page = metadata_parser.MetadataParser(html=HTML, support_malformed=True)

or::

    >>> parsed = page.parse(html=html, support_malformed=True)
    >>> parsed = page.parse(html=html, support_malformed=False)

The above options will support parsing common malformed options.  Currently
this only looks at alternate (improper) ways of producing twitter tags, but may
be expanded.

Notes
=====

when building on Python3, a ``static`` toplevel directory may be needed

This library was originally based on Erik River's
`opengraph module <https://github.com/erikriver/opengraph>`_. Something more
aggressive than Erik's module was needed, so this project was started.