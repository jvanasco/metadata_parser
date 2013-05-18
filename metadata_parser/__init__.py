import gzip
import httplib
import re
import struct
import urllib2
import urlparse
import zlib

try:
    from bs4 import BeautifulSoup
except:
    from BeautifulSoup import BeautifulSoup

try:
    from io import BytesIO as _StringIO
except ImportError:
    try:
        from cStringIO import StringIO as _StringIO
    except ImportError:
        from StringIO import StringIO as _StringIO


RE_url= re.compile("""(https?\:\/\/[^\/]*(?:\:[\d]+)?)?(.*)""", re.I)

RE_bad_title= re.compile("""(?:<title>|&lt;title&gt;)(.*)(?:<?/title>|(?:&lt;)?/title&gt;)""", re.I)

RE_url_parts= re.compile("""(https?\:\/\/[^\/]*(?:\:[\d]+?)?)(\/[^?#]*)?""", re.I)


ONLY_PARSE_SAFE_FILES = False
PARSE_SAFE_FILES = ( 'html','txt','json','htm','xml','php','asp','aspx','ece','xhtml','cfm','cgi')

## This is taken from the following blogpost.  thanks.
## http://hustoknow.blogspot.com/2011/05/urlopen-opens-404.html

class CustomHTTPRedirectHandler(urllib2.HTTPRedirectHandler):
    # If a redirect happens within a 301, we deal with it here.

    def redirect_request(self, req, fp, code, msg, hdrs, newurl):
        parsed_url = urlparse.urlparse(newurl)

        # See http://code.google.com/web/ajaxcrawling/docs/getting-started.html
        #
        # Strip out the hash fragment, since fragments are never (by
        # specification) sent to the server.  If you do, a 404 error can occur.
        # urllib2.urlopen() also will die a glorius death if you try, so you must
        # remove it.   See http://stackoverflow.com/questions/3798422 for more info.
        # Facebook does not really conform to the Google standard, so we can't
        # send the fragment as _escaped_fragment_=key=value.

        # Strip out the URL fragment and reconstruct everything if a hash tag exists.
        if newurl.find('#') != -1:
            newurl = "%s://%s%s" % (parsed_url.scheme, parsed_url.netloc, parsed_url.path)
        return urllib2.HTTPRedirectHandler.redirect_request(self, req, fp, code, msg, hdrs, newurl)

CustomHTTPRedirectOpener = urllib2.build_opener(CustomHTTPRedirectHandler())


class NotParsable(Exception):
    message= None
    raised= None

    def __init__( self , message='' , raised=None ):
        self.message = message
        self.raised = raised

    def __str__( self ):
        return "ApiError: %s | %s" % ( self.message , self.raised )

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

    """
    url = None
    url_actual = None
    url_info = None
    strategy= None
    metadata= None
    LEN_MAX_TITLE = 255

    og_minimum_requirements= [ 'title', 'type' , 'image' , 'url' ]
    twitter_sections= ['card','title','site','description']
    strategy= ['og','dc','meta','page']


    def __init__(self, url=None, html=None, strategy=None, url_data=None, url_headers=None, force_parse=False ):
        self.metadata= {
            'og':{},
            'meta':{},
            'dc':{},
            'page':{},
            'twitter':{}
        }
        if strategy:
            self.strategy= strategy
        self.url = url
        if html is None:
            html= self.fetch_url( url_data=url_data, url_headers=url_headers, force_parse=force_parse )
        self.parser(html, force_parse=force_parse)


    def is_opengraph_minimum(self):
        """returns true/false if the page has the minimum amount of opengraph tags"""
        return all([hasattr(self, attr) for attr in self.og_minimum_requirements])


    def fetch_url(self, url_data=None, url_headers=None , force_parse=False ):
        """fetches the url and returns it.  this was busted out so you could subclass.
        """
        # should we even download/parse this?
        if not force_parse and ONLY_PARSE_SAFE_FILES :
            url_parts= RE_url_parts.match(self.url).groups()
            if url_parts[1] :
                url_fpath = url_parts[1].split('.')
                if len(url_fpath) == 0:
                    # i have no idea what this file is , it's likely using a directory index
                    pass
                elif len(url_fpath) > 1:
                    url_fext = url_fpath[-1]
                    if url_fext in PARSE_SAFE_FILES :
                        pass
                    else:
                        raise NotParsable("I don't know what this file is")


        ## borrowing some ideas from http://code.google.com/p/feedparser/source/browse/trunk/feedparser/feedparser.py#3701

        req= None
        raw= None

        if not url_headers:
            url_headers= {}
            
        # if someone does usertracking with sharethis.com, they get a hashbang like this: http://example.com/page#.UHeGb2nuVo8
        # that fucks things up.
        url = self.url.split('#')[0]
        
        try :
            req = urllib2.Request(url, url_data, url_headers)
            req.add_header('Accept-encoding', 'gzip, deflate')
            raw = CustomHTTPRedirectOpener.open(req)
            html = raw.read()
        except httplib.BadStatusLine , error :
            raise NotParsableFetchError(raised=error)
        except httplib.InvalidURL , error :
            raise NotParsableFetchError(raised=error)
        except httplib.HTTPException , error :
            raise NotParsableFetchError(raised=error)
        except urllib2.HTTPError , error:
            raise NotParsableFetchError(raised=error)
        except urllib2.URLError , error :
            raise NotParsableFetchError(raised=error)
        except Exception as error:
            raise NotParsableFetchError(raised=error)

        # lowercase all of the HTTP headers for comparisons per RFC 2616
        http_headers = dict((k.lower(), v) for k, v in raw.headers.items())
        if 'gzip' in http_headers.get('content-encoding', ''):
            try:
                html = gzip.GzipFile(fileobj=_StringIO(html)).read()
            except (IOError, struct.error), e:
                try:
                    # apparently the gzip module isn't too good and doesn't follow spec
                    # here's a wonderful workaround
                    # http://stackoverflow.com/questions/4928560/how-can-i-work-with-gzip-files-which-contain-extra-data
                    gzipfile= _StringIO(html)
                    html = zlib.decompress(gzipfile.read()[10:], -zlib.MAX_WBITS)
                except:
                    raise
        elif 'deflate' in http_headers.get('content-encoding', ''):
            try:
                html = zlib.decompress(html)
            except zlib.error, e:
                try:
                    # The data may have no headers and no checksum.
                    html = zlib.decompress(html, -15)
                except zlib.error, e:
                    raise

        self.url_actual= raw.geturl()
        self.url_info= raw.info()
        return html


    def absolute_url( self, link=None ):
        """makes the url absolute, as sometimes people use a relative url. sigh.
        """
        if not link:
           link= self.url_actual
        if not link:
            return None
        rval = link
        link_parts= RE_url.match(link)
        if link_parts:
            grouped= link_parts.groups()
            if grouped[0]:
                pass # just return the link/rval
            else:
                # fix with a domain if we can
                if self.url_actual :
                    domain= RE_url.match(self.url_actual).groups()[0]
                    rval= "%s%s" % ( domain , link )
                elif self.url :
                    domain= RE_url.match(self.url).groups()[0]
                    rval= "%s%s" % ( domain , link )
        return rval


    def parser(self, html, force_parse=False ):
        """parses the html
        """
        if not isinstance(html,BeautifulSoup):
            html = unicode(html,errors='ignore')
            try:
                doc = BeautifulSoup(html,"lxml")
            except:
                doc = BeautifulSoup(html)
        else:
            doc = html

        # let's ensure that we have a real document...
        if not doc or not doc.html or not doc.html.head :
            return

        ogs = doc.html.head.findAll('meta',attrs={'property':re.compile(r'^og')})
        for og in ogs:
            try:
                self.metadata['og'][og[u'property'][3:]] = og[u'content']
            except ( AttributeError , KeyError ):
                pass

        twitters = doc.html.head.findAll('meta',attrs={'name':re.compile(r'^twitter')})
        for twitter in twitters:
            try:
                self.metadata['twitter'][twitter[u'name'][8:]] = twitter[u'value']
            except ( AttributeError , KeyError ):
                pass

        # pull the text off the title
        try:
            self.metadata['page']['title']= doc.html.head.title.text
            if len(self.metadata['page']['title']) > self.LEN_MAX_TITLE:
                broken_title= RE_bad_title.match("%s"%doc.html.head.title)
                if broken_title:
                    self.metadata['page']['title']= broken_title.groups(0)[0][:self.LEN_MAX_TITLE]
        except AttributeError:
            pass

        # is there an image_src?
        image= doc.findAll('link', attrs={'rel':re.compile("^image_src$", re.I)})
        if image:
            try:
                img = image[0]['href']
                self.metadata['page']['image']= img
            except KeyError:
                img = image[0]['content']
                self.metadata['page']['image']= img
            except:
                pass

        # figure out the canonical url
        canonical= doc.findAll('link', attrs={'rel':re.compile("^canonical$", re.I)})
        if canonical:
            try:
                link= canonical[0]['href']
                self.metadata['page']['canonical']= link
            except KeyError:
                link= canonical[0]['content']
                self.metadata['page']['canonical']= link
            except:
                pass

        # pull out all the metadata
        meta= doc.html.head.findAll(name='meta')
        for m in meta:
            try:
                k = None
                v = None
                attrs = m.attrs
                k = None
                if 'name' in attrs:
                    k= 'name'
                elif 'property' in attrs:
                    k= 'property'
                elif 'http-equiv' in attrs:
                    k= 'http-equiv'
                if k:
                    k= attrs[k].strip()
                    if 'content' in attrs:
                        v= attrs['content'].strip()
                    if ( len(k) > 3 ) and ( k[:3] == 'dc:'):
                        self.metadata['dc'][k[3:]]= v
                    else:
                        self.metadata['meta'][k]= v
            except AttributeError:
                pass


    def get_metadata(self,field,strategy=None):
        """looks for the field in various stores.  defaults to the core strategy, though you may specify a certain item.  if you search for 'all' it will return a dict of all values."""
        if strategy:
            _strategy= strategy
        else:
            _strategy= self.strategy
        if _strategy == 'all':
            rval= {}
            for store in self.metadata:
                if field in self.metadata[store]:
                    rval[store]= self.metadata[store][field]
            return rval
        for store in _strategy:
            if store in self.metadata:
                if field in self.metadata[store]:
                    return self.metadata[store][field]
        return None


    def get_discrete_url(self,og_first=True,canonical_first=False):
        """convenience method."""
        og = self.get_metadata('url',strategy=['og'])
        canonical = self.get_metadata('canonical',strategy=['page'])
        rval= []
        if og_first:
             rval.extend((og,canonical))
        elif canonical_first:
             rval.extend((canonical,og))
        for i in rval:
            if i:
                return self.absolute_url( i )
        return self.absolute_url()
