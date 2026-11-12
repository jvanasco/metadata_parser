HTML entity regression coverage
===============================

``test_html_entities.py`` runs a default set of 53 common and essential names:
markup delimiters, whitespace, punctuation, currency, accented letters, and
common mathematical symbols. It retains the ``curren`` and ``curlywedge``
regressions from issue #65, as well as a multi-code-point reference.

Every name is checked with and without a trailing semicolon, in title text and
quoted ``meta``/Open Graph attributes. Brackets around the decoded value prevent
normal metadata whitespace stripping from hiding whitespace entities.

The advanced test uses Python's ``html.entities.html5`` data table, which maps
the HTML5 named character references to Unicode strings. It does not use
``html.unescape`` or a parser's output to generate expected results. The current
table contains 2,125 distinct names, including 106 names with legacy
semicolon-free spellings. All names are tested in both forms, including the
semicolon-free forms that the standard does not permit as complete references.

Sources:

* `HTML named character references <https://html.spec.whatwg.org/multipage/named-characters.html>`_
* `Python's HTML5 entity table <https://docs.python.org/3/library/html.entities.html>`_

Running the tests
-----------------

The common set runs by default. Install the ``testing-backends`` extra to
include html5lib; otherwise its cases are explicitly skipped. lxml is required
by the normal testing extra, and html.parser is part of Python::

    python -m pip install -e '.[testing-backends]'
    python -m pytest tests/test_html_entities.py

Enable the exhaustive set with ``--html5-entities``. This adds the full matrix
to the common tests. To run only that matrix::

    python -m pytest tests/test_html_entities.py --html5-entities -m html5_entities

With all three backends installed, the exhaustive matrix has 12,750 cases.
The advanced cases are skipped unless explicitly enabled.

Tracked backend differences
---------------------------

The following baseline was verified on Python 3.14.6, BeautifulSoup 4.13.5,
lxml 6.1.3 with libxml2 2.14.6, and html5lib 1.1. Tests assert these expectations;
they do not accept arbitrary differences or automatically change expectations
based on installed versions. Test IDs identify the backend, entity, and
semicolon form, and assertion messages show escaped actual values.

* With a semicolon, every backend decodes each reference to the HTML5 table's
  Unicode value, including values containing multiple code points.
* Without a semicolon, the legacy names (such as ``amp``, ``nbsp``, and
  ``curren``) decode in both title text and quoted metadata attributes.
* For the other names without a semicolon, html.parser decodes the full name
  in title text. lxml and html5lib instead consume the longest recognized
  legacy prefix, if one exists, or preserve the reference literally.
* In quoted metadata attributes, all three backends preserve those other
  semicolon-free names literally. A legacy prefix followed by a letter or
  equals sign is also preserved, as tested by URL query parameters such as
  ``&current=2`` and ``&amp=2``.

Examples without semicolons:

================= ==================== ==================== ====================
Reference         lxml/html5lib title  html.parser title    Quoted metadata
================= ==================== ==================== ====================
``&curren``       U+00A4               U+00A4               U+00A4
``&apos``         literal ``&apos``    U+0027               literal ``&apos``
``&curlywedge``   literal reference    U+22CF               literal reference
``&notin``        U+00AC + ``in``      U+2209               literal ``&notin``
``&NewLine``      literal reference    U+000A               literal reference
================= ==================== ==================== ====================

This suite tracks named references in the package's metadata extraction path.
It does not claim to test all HTML tokenizer contexts or numeric references.
