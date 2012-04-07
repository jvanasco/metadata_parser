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


Usage
==============

**From an URL**

>>> import metadata_parser
>>> page = metadata_parser.MetadataParser(url="http://www.cnn.com")
>>> print page.metadata
>>> print page.get_field('title')
>>> print page.get_field('title',strategy='og')

**From HTML**

>>> HTML = """<here>"""
>>> page = metadata_parser.MetadataParser(html=HTML)
>>> print page.metadata
>>> print page.get_field('title')
>>> print page.get_field('title',strategy='og')
