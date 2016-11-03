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
3. URL Validation is not RFC compliant, but "Real World" compliant

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




Usage
==============

**From an URL**

>>> import metadata_parser
>>> page = metadata_parser.MetadataParser(url="http://www.cnn.com")
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
