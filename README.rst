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
1. This requires BeautifulSoup 3 or 4.  If it can import bs4 it does, otherwise it tries BeautifulSoup (3)
2. For speed, it will instantiate a BeautifulSoup parser with lxml , and fall back to 'none' (the internal pure python) if it can't load lxml

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
