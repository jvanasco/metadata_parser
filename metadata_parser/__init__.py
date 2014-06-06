import re
import requests

from bs4 import BeautifulSoup
import urlparse


RE_bad_title = re.compile(
    """(?:<title>|&lt;title&gt;)(.*)(?:<?/title>|(?:&lt;)?/title&gt;)""", re.I)

PARSE_SAFE_FILES = ('html', 'txt', 'json', 'htm', 'xml',
                    'php', 'asp', 'aspx', 'ece', 'xhtml', 'cfm', 'cgi')
                    



def is_parsed_valid_url(parsed):
    """returns bool"""
    assert isinstance( parsed, urlparse.ParseResult )
    if not all( (parsed.scheme, parsed.hostname) ):
        return False
    return True

def is_parsed_valid_relative(parsed):
    """returns bool"""
    assert isinstance( parsed, urlparse.ParseResult )
    if parsed.path and not any( (parsed.scheme, parsed.hostname) ):
        return True
    return False

def parsed_to_relative(parsed):
    """turns a parsed url into a full relative url"""
    assert isinstance( parsed, urlparse.ParseResult )
    _path = parsed.path
    ## cleanup, might be unnecessary now
    if _path and _path[0] != "/":
        ## prepend a slash
        _path = "/%s" % _path
    if parsed.query :
        _path += "?" + parsed.query
    if parsed.fragment :
        _path += "#" + parsed.fragment
    return _path    

def is_url_valid(url):
    """tries to parse a url. if valid returns `urlparse.ParseResult` (boolean eval is True); if invalid returns `False`"""
    if url is None:
        return False
    parsed = urlparse.urlparse(url)
    if is_parsed_valid_url(parsed):
        return parsed
    return False


def url_to_absolute_url( url_test, url_fallback=None ):
    ## this shouldn't happen, but does
    if url_test is None and url_fallback is not None:
        return url_fallback
        
    parsed = urlparse.urlparse( url_test )
    
    _path = parsed.path
    if _path :
        ## sanity check
        # some stock plugins create invalid urls/files like '/...' in meta-data
        if _path[0] != "/":
          ## prepend a slash
          _path = "/%s" % _path
        known_invalid_plugins = [ '/...', ]  
        if _path in known_invalid_plugins :
            return url_fallback
        
    # finally, fix the path
    ## this isn't nested, because we could have kwargs
    _path = parsed_to_relative( parsed )
    
    if not _path:
        ## so if our _path is BLANK , fuck it.
        ## this can happen if someone puts in "" for the canonical
        return url_fallback

    rval = None
    
    # we'll use a placeholder for a source 'parsed' object that has a domain...
    parsed_domain_source = None
    
    # if we have a valid URL ( OMFG, PLEASE )...
    if is_parsed_valid_url( parsed ):
        parsed_domain_source = parsed
    else:
        ## ok, the URL isn't valid
        ## can we re-assemble it...
        if url_fallback :
            parsed_fallback = urlparse.urlparse( url_fallback )
            if is_parsed_valid_url( parsed_fallback ):
                parsed_domain_source = parsed_fallback
    if parsed_domain_source:
        rval = "%s://%s%s" % (parsed_domain_source.scheme, parsed_domain_source.netloc, _path)
    return rval




class NotParsable(Exception):

    def __init__(self, message='', raised=None, code=None):
        self.message = message
        self.raised = raised
        self.code = code

    def __str__(self):
        return "ApiError: %s | %s | %s" % (self.message, self.code, self.raised)


class NotParsableFetchError(NotParsable):
    pass


class MetadataParser(object):

    """turns text or a URL into a dict of dicts, extracting as much relvant metadata as possible.

        the 'keys' will be either the 'name' or 'property' attribute of the node.

        the attribute's prefix are removed when storing into it's bucket
        eg:
            og:title -> 'og':{'title':''}

        metadata is stored into subgroups:

        page
            extracted from page elements
            saved into MetadataParser.metadata['page']
            example:
                <head><title>Awesome</title></head>
                MetadataParser.metadata = { 'page': { 'title':'Awesome' } }

        opengraph
            has 'og:' prefix
            saved into MetadataParser.metadata['og']
            example:
                <meta property="og:title" content="Awesome"/>
                MetadataParser.metadata = { 'og': { 'og:title':'Awesome' } }

        dublin core
            has 'dc:' prefix
            saved into MetadataParser.metadata['dc']
            example:
                <meta property="dc:title" content="Awesome"/>
                MetadataParser.metadata = { 'dc': { 'dc:title':'Awesome' } }

        meta
            has no prefix
            saved into MetadataParser.metadata['meta']
            example:
                <meta property="title" content="Awesome"/>
                MetadataParser.metadata = { 'meta': { 'dc:title':'Awesome' } }

        NOTE:
            passing in ssl_verify=False will turn off ssl verification checking in the requests library.
            this can be necessary on development machines

    """
    url = None
    url_actual = None
    strategy = None
    metadata = None
    LEN_MAX_TITLE = 255
    only_parse_file_extensions = None

    og_minimum_requirements = ['title', 'type', 'image', 'url']
    twitter_sections = ['card', 'title', 'site', 'description']
    strategy = ['og', 'dc', 'meta', 'page']

    def __init__(self, url=None, html=None, strategy=None, url_data=None, url_headers=None, force_parse=False, ssl_verify=True, only_parse_file_extensions=None, force_parse_invalid_content_type=False ):
        """
        creates a new `MetadataParser` instance.
        
        kwargs:
            `url` 
                url to parse
            `html`
                instead of a url, parse raw html
            `strategy`
                default : None
                sets default metadata strategy ( ['og', 'dc', 'meta', 'page'] )
                see also `MetadataParser.get_metadata()`
            `url_data`
                data passed to `requests` library as `params`
            `url_headers`
                data passed to `requests` library as `headers`
            `force_parse` 
                default: False
                force parsing invalid content
            `ssl_verify` 
                default: True
                disable ssl verification, sometimes needed in development
            `only_parse_file_extensions`
                default: None
                set a list of valid file extensions.  see `metadata_parser.PARSE_SAFE_FILES` for an example list
            `force_parse_invalid_content_type`
                default: False
                force parsing invalid content types
                by default this will only parse text/html content
        """
        self.metadata = {
            'og': {},
            'meta': {},
            'dc': {},
            'page': {},
            'twitter': {}
        }
        if strategy:
            self.strategy = strategy
        if url is not None:
            url = url.strip()
        self.url = url
        self.url_actual = url
        self.ssl_verify = ssl_verify
        self.response = None
        self.response_headers = {}
        if only_parse_file_extensions is not None:
            self.only_parse_file_extensions = only_parse_file_extensions
        if html is None:
            html = self.fetch_url( url_data = url_data, url_headers = url_headers,
                force_parse = force_parse, 
                force_parse_invalid_content_type = force_parse_invalid_content_type )
        self.parser(html, force_parse=force_parse)

    def is_opengraph_minimum(self):
        """returns true/false if the page has the minimum amount of opengraph tags"""
        return all([hasattr(self, attr) for attr in self.og_minimum_requirements])

    def fetch_url(self, url_data=None, url_headers=None, force_parse=False, force_parse_invalid_content_type=False ):
        """fetches the url and returns it.  this was busted out so you could subclass.
        """
        # should we even download/parse this?
        if not force_parse and self.only_parse_file_extensions is not None :
            parsed = urlparse.urlparse( self.url )
            path = parsed.path
            if path:
                url_fpath = path.split('.')
                if len(url_fpath) == 0:
                    # i have no idea what this file is, it's likely using a
                    # directory index
                    pass
                elif len(url_fpath) > 1:
                    url_fext = url_fpath[-1]
                    if url_fext in self.only_parse_file_extensions:
                        pass
                    else:
                        raise NotParsable("I don't know what this file is")

        # borrowing some ideas from
        # http://code.google.com/p/feedparser/source/browse/trunk/feedparser/feedparser.py#3701
        if not url_headers:
            url_headers = {}

        # if someone does usertracking with sharethis.com, they get a hashbang like this: http://example.com/page#.UHeGb2nuVo8
        # that fucks things up.
        url = self.url.split('#')[0]

        r = None
        try:
            # requests gives us unicode and the correct encoding, yay
            r = requests.get(url, params=url_data, headers=url_headers,
                             allow_redirects=True, verify=self.ssl_verify)
                             
            content_type = None
            if 'content-type' in r.headers :
                content_type = r.headers['content-type']
                ## content type can have a character encoding in it...
                content_type = [ i.strip() for i in content_type.split(';') ]
                content_type = content_type[0].lower()

            if ( content_type is None or ( content_type != 'text/html' ) ) and not force_parse_invalid_content_type  :
                raise NotParsable("I don't know what type of file this is! content-type:'[%s]" % content_type )
        
            html = r.text
            self.response = r

            # lowercase all of the HTTP headers for comparisons per RFC 2616
            self.response_headers = dict((k.lower(), v)
                                         for k, v in r.headers.items())
            self.url_actual = r.url

            if r.status_code != 200:
                raise NotParsableFetchError(
                    message="Status Code is not 200", code=r.status_code)

        except requests.exceptions.RequestException as error:
            raise NotParsableFetchError(
                message="Error with `requests` library.  Inspect the `raised` attribute of this error.", raised=error)

        return html



    def absolute_url(self, link=None):
        """makes the url absolute, as sometimes people use a relative url. sigh.
        """
        url_fallback = self.url_actual or self.url or None
        return url_to_absolute_url( link, url_fallback = url_fallback)
        


    def parser(self, html, force_parse=False):
        """parses the html
        """
        if not isinstance(html, BeautifulSoup):
            try:
                doc = BeautifulSoup(html, "lxml")
            except:
                doc = BeautifulSoup(html)
        else:
            doc = html

        # let's ensure that we have a real document...
        if not doc or not doc.html or not doc.html.head:
            return

        ogs = doc.html.head.findAll(
            'meta', attrs = { 'property' : re.compile(r'^og') } )
        for og in ogs:
            try:
                self.metadata['og'][og['property'][3:]] = og['content'].strip()
            except (AttributeError, KeyError):
                pass

        twitters = doc.html.head.findAll(
            'meta', attrs = { 'name' : re.compile(r'^twitter') } )
        for twitter in twitters:
            try:
                self.metadata['twitter'][
                    twitter['name'][8:]] = twitter['value'].strip()
            except (AttributeError, KeyError):
                pass

        # pull the text off the title
        try:
            _title_text = doc.html.head.title.text
            if len(_title_text) > self.LEN_MAX_TITLE:
                _title_text = _title_text[:self.LEN_MAX_TITLE]
            self.metadata['page']['title'] = _title_text

        except AttributeError:
            pass

        # is there an image_src?
        image = doc.findAll(
            'link', attrs = { 'rel' : re.compile("^image_src$", re.I) } )
        if image:
            try:
                img = image[0]['href'].strip()
                self.metadata['page']['image'] = img
            except KeyError:
                img = image[0]['content'].strip()
                self.metadata['page']['image'] = img
            except:
                pass

        # figure out the canonical url
        canonical = doc.findAll(
            'link', attrs = { 'rel' : re.compile("^canonical$", re.I) } )
        if canonical:
            try:
                link = canonical[0]['href'].strip()
                self.metadata['page']['canonical'] = link
            except KeyError:
                link = canonical[0]['content'].strip()
                self.metadata['page']['canonical'] = link
            except:
                pass

        # pull out all the metadata
        meta = doc.html.head.findAll(name='meta')
        for m in meta:
            try:
                k = None
                v = None
                attrs = m.attrs
                k = None
                if 'name' in attrs:
                    k = 'name'
                elif 'property' in attrs:
                    k = 'property'
                elif 'http-equiv' in attrs:
                    k = 'http-equiv'
                if k:
                    k = attrs[k].strip()
                    if 'content' in attrs:
                        v = attrs['content'].strip()
                    if (len(k) > 3) and (k[:3] == 'dc:'):
                        self.metadata['dc'][k[3:]] = v
                    else:
                        self.metadata['meta'][k] = v
            except AttributeError:
                pass

    def get_metadata(self, field, strategy=None):
        """looks for the field in various stores.  defaults to the core strategy, though you may specify a certain item.  if you search for 'all' it will return a dict of all values."""
        if strategy:
            _strategy = strategy
        else:
            _strategy = self.strategy
        if _strategy == 'all':
            rval = {}
            for store in self.metadata:
                if field in self.metadata[store]:
                    rval[store] = self.metadata[store][field]
            return rval
        for store in _strategy:
            if store in self.metadata:
                if field in self.metadata[store]:
                    return self.metadata[store][field]
        return None


    def get_discrete_url(self, og_first=True, canonical_first=False, allow_invalid=False ):
        """convenience method.
        
            if `allow_invalid` is True, it will return the raw data.
            if `allow_invalid` is False (default), it will try to correct the data (relative to absolute) or reset to None.
        """
        
        og = self.get_metadata('url', strategy=['og'])
        canonical = self.get_metadata('canonical', strategy=['page'])

        if not allow_invalid:
            # fallback url is used to drop a domain
            url_fallback = self.url_actual or self.url or None

            if og and not is_url_valid( og ):
                og = url_to_absolute_url( og, url_fallback = url_fallback )      
        
            if canonical and not is_url_valid( canonical ):
                canonical = url_to_absolute_url( canonical, url_fallback = url_fallback )      

        rval = []
        if og_first:
            rval = (og, canonical)
        elif canonical_first:
            rval = (canonical, og)
            
        for i in rval:
            if i:
                return i

        return self.absolute_url()
