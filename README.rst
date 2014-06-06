MetadataParser is a python module for pulling metadata out of web documents.

It requires BeautifulSoup , and was largely based on Erik River's opengraph module ( https://github.com/erikriver/opengraph ).

I needed something more aggressive than Erik's module , so had to fork.


Installation
=============

pip install metadata_parser

Features
=============

* it pulls as much metadata out of a document as possible
* you can set a 'strategy' for finding metadata ( ie, only accept opengraph or page attributes )

Notes
=============
1. This requires BeautifulSoup 4.
2. For speed, it will instantiate a BeautifulSoup parser with lxml , and fall back to 'none' (the internal pure python) if it can't load lxml

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

The MetadataParser object also wraps some convenience functions , which can be used otherwise , that are designed to turn alleged urls into well formed urls.

For example, you may pull a page:

	http://www.example.com/path/to/file.html
	
and that file indicates a canonical url which is simple "/file.html".

This package will try to 'remount' the canonical url to the absolute url of "http://www.example.com/file.html" .  It will return None if the end result is not a valid url.

This all happens under-the-hood, and is honestly really useful when dealing with indexers and spiders.


Usage
==============

**From an URL**

>>> import metadata_parser
>>> page = metadata_parser.MetadataParser(url="http://www.cnn.com")
>>> print page.metadata
>>> print page.get_field('title')
>>> print page.get_field('title',strategy='og')
>>> print page.get_field('title',strategy='page,og,dc')

**From HTML**

>>> HTML = """<here>"""
>>> page = metadata_parser.MetadataParser(html=HTML)
>>> print page.metadata
>>> print page.get_field('title')
>>> print page.get_field('title',strategy='og')
>>> print page.get_field('title',strategy='page,og,dc')
