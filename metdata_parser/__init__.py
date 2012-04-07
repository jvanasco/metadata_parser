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
    _url = None
    strategy= None
    metadata= None

    og_requirements= [ 'og_title', 'og_type' , 'og_image' , 'og_url' ]


    def __init__(self, url=None, html=None, strategy='og,dc,meta,page'):
        self.metadata= {
            'og':{},
            'meta':{},
            'dc':{},
            'page':{},
        }
        self.strategy= strategy.split(',')
        if url is not None:
            html= self.fetch(url)
        self.parser(html)


    def is_valid_opengraph(self):
        return all([hasattr(self, attr) for attr in self.og_requirements])


    def fetch(self, url):
        """
        """
        self._url = url
        raw = urllib2.urlopen(url)
        html = raw.read()


    def parser(self, html):
        """
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
            canonical_parts= RE_url.match(link)
            if canonical_parts:
                grouped= canonical_parts.groups()
                if grouped[0]:
                    pass
                else:
                    # fix with a domain if we can
                    if self._url :
                        domain= RE_url.match(self._url).groups()[0]
                        link= "%s%s" % ( domain , link )
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
            if k:
                k= attrs[k].strip()
                if 'content' in attrs:
                    v= attrs['content'].strip()
            if ( len(k) > 3 ) and ( k[:3] == 'dc:'):
                self.metadata['dc'][k[3:]]= v
            else:
                self.metadata['meta'][k]= v


    def get_metadata(self,field,strategy=None):
        if strategy:
            _strategy= strategy.split(',')
        else:
            _strategy= self.strategy
        for store in _strategy:
            if field in self.metadata[store]:
                return self.metadata[store][field]
        
    
    
    
    