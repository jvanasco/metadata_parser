import re
import urllib2
try:
    from bs4 import BeautifulSoup
except:
    from BeautifulSoup import BeautifulSoup


RE_url= re.compile("""(https?\:\/\/[^\/]*(?:\:[\d]+)?)?(.*)""", re.I)

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
    strategy= None
    metadata= None

    og_minimum_requirements= [ 'title', 'type' , 'image' , 'url' ]
    strategy= ['og','dc','meta','page']


    def __init__(self, url=None, html=None, strategy=None):
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
            html= self.fetch_url()
        self.parser(html)


    def is_opengraph_minimum(self):
        """returns true/false if the page has the minimum amount of opengraph tags"""
        return all([hasattr(self, attr) for attr in self.og_minimum_requirements])


    def fetch_url(self):
        """fetches the url and returns it.  this was busted out so you could subclass.
        """
        raw = urllib2.urlopen(self.url)
        html = raw.read()
        return html
        

    def absolute_url( self, link=None ):
        """makes the url absolute, as sometimes people use a relative url. sigh.
        """
        rval = link
        link_parts= RE_url.match(link)
        if link_parts:
            grouped= link_parts.groups()
            if grouped[0]:
                pass # just return the link/rval
            else:
                # fix with a domain if we can
                if self.url :
                    domain= RE_url.match(self.url).groups()[0]
                    rval= "%s%s" % ( domain , link )
        return rval


    def parser(self, html):
        """parses the html
        """
        if not isinstance(html,BeautifulSoup):
            try:
                doc = BeautifulSoup(html,"lxml")
            except:
                doc = BeautifulSoup(html)
        else:
            doc = html

        ogs = doc.html.head.findAll(property=re.compile(r'^og'))
        for og in ogs:
            self.metadata['og'][og[u'property'][3:]]=og[u'content']

        # pull the text off the title
        self.metadata['page']['title']= doc.html.head.title.text
        
        # figure out the canonical url
        canonical= doc.findAll('link', attrs={'rel':re.compile("^canonical$", re.I)})
        if canonical:
            link= canonical[0]['href']
            self.metadata['page']['canonical']= link

        # pull out all the metadata
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
        return None
        