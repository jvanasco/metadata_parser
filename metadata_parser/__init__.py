import re
import urllib2
import urlparse

try:
    from bs4 import BeautifulSoup
except:
    from BeautifulSoup import BeautifulSoup


RE_url= re.compile("""(https?\:\/\/[^\/]*(?:\:[\d]+)?)?(.*)""", re.I)

RE_bad_title= re.compile("""(?:<title>|&lt;title&gt;)(.*)(?:<?/title>|(?:&lt;)?/title&gt;)""", re.I)

RE_url_parts= re.compile("""(https?\:\/\/[^\/]*(?:\:[\d]+?)?)(\/[^?#]*)?""", re.I)



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
    strategy= ['og','dc','meta','page']


    def __init__(self, url=None, html=None, strategy=None, url_data=None, url_headers=None, force_parse=False ):
        self.metadata= {
            'og':{},
            'meta':{},
            'dc':{},
            'page':{},
        }
        if strategy:
            self.strategy= strategy
        self.url = url
        if html is None:
            html= self.fetch_url( url_data=url_data, url_headers=url_headers, force_parse=False )
        self.parser(html, force_parse=force_parse)


    def is_opengraph_minimum(self):
        """returns true/false if the page has the minimum amount of opengraph tags"""
        return all([hasattr(self, attr) for attr in self.og_minimum_requirements])


    def fetch_url(self, url_data=None, url_headers=None , force_parse=False ):
        """fetches the url and returns it.  this was busted out so you could subclass.
        """
        # should we even download/parse this?
        if not force_parse:
            url_parts= RE_url_parts.match(self.url).groups()
            if url_parts[1] :
                url_fpath = url_parts[1].split('.')
                if len(url_fpath) == 0:
                    # i have no idea what this file is
                    pass
                elif len(url_fpath) > 1:
                    url_fext = url_fpath[-1]
                    if url_fext in ( 'html','txt','json','htm','xml' ):
                        pass
                    else:
                        raise NotParsable("I don't know what this file is")
        raw= None
        req= None
        if url_data or url_headers:
            req = urllib2.Request(self.url, url_data, url_headers)
            raw = CustomHTTPRedirectOpener.open(req)
        else:
            req = urllib2.Request(self.url)
            raw = CustomHTTPRedirectOpener.open(req)
        html = raw.read()
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
            try:
                doc = BeautifulSoup(html,"lxml")
            except:
                doc = BeautifulSoup(html)
        else:
            doc = html

        try:
            ogs = doc.html.head.findAll(property=re.compile(r'^og'))
            for og in ogs:
                self.metadata['og'][og[u'property'][3:]]=og[u'content']
        except AttributeError:
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
        try:
            meta= doc.html.head.findAll(name='meta')
            for m in meta:
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
