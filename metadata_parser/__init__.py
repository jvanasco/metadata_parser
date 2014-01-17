import re
import requests

from bs4 import BeautifulSoup

#RE_url = re.compile("""(https?\:\/\/[^\/]*(?:\:[\d]+)?)(\/.*)?""", re.I)
RE_url = re.compile("""(https?\:\/\/[^\/]*(?:\:[\d]+)?)?(.*)""", re.I)

RE_bad_title = re.compile(
    """(?:<title>|&lt;title&gt;)(.*)(?:<?/title>|(?:&lt;)?/title&gt;)""", re.I)

RE_url_parts = re.compile(
    """(https?\:\/\/[^\/]*(?:\:[\d]+?)?)(\/[^?#]*)?""", re.I)


ONLY_PARSE_SAFE_FILES = False
PARSE_SAFE_FILES = ('html', 'txt', 'json', 'htm', 'xml',
                    'php', 'asp', 'aspx', 'ece', 'xhtml', 'cfm', 'cgi')

# This is taken from the following blogpost.  thanks.
# http://hustoknow.blogspot.com/2011/05/urlopen-opens-404.html


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

    og_minimum_requirements = ['title', 'type', 'image', 'url']
    twitter_sections = ['card', 'title', 'site', 'description']
    strategy = ['og', 'dc', 'meta', 'page']

    def __init__(self, url=None, html=None, strategy=None, url_data=None, url_headers=None, force_parse=False, ssl_verify=True):
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
        if html is None:
            html = self.fetch_url(url_data=url_data, url_headers=url_headers,
                                  force_parse=force_parse)
        self.parser(html, force_parse=force_parse)

    def is_opengraph_minimum(self):
        """returns true/false if the page has the minimum amount of opengraph tags"""
        return all([hasattr(self, attr) for attr in self.og_minimum_requirements])

    def fetch_url(self, url_data=None, url_headers=None, force_parse=False):
        """fetches the url and returns it.  this was busted out so you could subclass.
        """
        # should we even download/parse this?
        if not force_parse and ONLY_PARSE_SAFE_FILES:
            url_parts = RE_url_parts.match(self.url).groups()
            if url_parts[1]:
                url_fpath = url_parts[1].split('.')
                if len(url_fpath) == 0:
                    # i have no idea what this file is , it's likely using a
                    # directory index
                    pass
                elif len(url_fpath) > 1:
                    url_fext = url_fpath[-1]
                    if url_fext in PARSE_SAFE_FILES:
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
            # requests gives us unicode and the correct encoding , yay
            r = requests.get(url, params=url_data, headers=url_headers,
                             allow_redirects=True, verify=self.ssl_verify)
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
        # set the fallback return value, in case we're parsing a bad url from the page
        rval_fallback = self.url_actual or None

        # use the self.url_actual as a fallback to check
        if not link:
            link = self.url_actual

        # ok, exit now if this is futile
        if not link:
            return rval_fallback

        rval = link
        link_parts = RE_url.match(link)
        if link_parts:
            ( link_part__host , link_part__local ) = link_parts.groups()

            if link_part__host :
                pass  # just return the link/rval
            else:
                if link_part__local :


                    ## prepend with a /
                    if link_part__local[0] != "/":
                        known_invalid_plugins = [ '...', ]  # some stock plugins create invalid urls like '...' in meta-data
                        if link_part__local in known_invalid_plugins :
                            return rval_fallback

                        link_part__local = "/%s" % link_part__local

                    # fix with a domain if we can
                    if self.url_actual:
                        domain = RE_url.match(self.url_actual).groups()[0].strip()
                        rval = "%s%s" % (domain, link_part__local)

                    elif self.url:
                        domain = RE_url.match(self.url).groups()[0].strip()
                        rval = "%s%s" % (domain, link_part__local)
                else:
                    # honestly, don't know how to address this part or if it could happen
                    pass
        return rval

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
            'meta', attrs={'property': re.compile(r'^og')})
        for og in ogs:
            try:
                self.metadata['og'][og['property'][3:]] = og['content'].strip()
            except (AttributeError, KeyError):
                pass

        twitters = doc.html.head.findAll(
            'meta', attrs={'name': re.compile(r'^twitter')})
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
            'link', attrs={'rel': re.compile("^image_src$", re.I)})
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
            'link', attrs={'rel': re.compile("^canonical$", re.I)})
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
        """convenience method."""
        
        og = self.get_metadata('url', strategy=['og'])
        canonical = self.get_metadata('canonical', strategy=['page'])
        
        if not allow_invalid:
            if og and not RE_url.match(og) :
                og = None
            if canonical and not RE_url.match(canonical):
                canonical = None

        rval = []
        if og_first:
            rval.extend((og, canonical))
        elif canonical_first:
            rval.extend((canonical, og))
            
        for i in rval:
            if i:
                return self.absolute_url(i)

        return self.absolute_url()
