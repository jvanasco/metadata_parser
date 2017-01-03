import logging
log = logging.getLogger(__name__)


# ------------------------------------------------------------------------------


__VERSION__ = '0.8.1'


# ------------------------------------------------------------------------------


# stdlib
import datetime
import re
import socket  # see `_compatible_sockets`
import _socket  # see `_compatible_sockets`
import warnings

# pypi
import requests
from bs4 import BeautifulSoup

# python 2/3
try:
    # Python 2 has a standard urlparse library
    from urlparse import urlparse, ParseResult
except:
    # Python 3 has the same library hidden in urllib.parse
    from urllib.parse import urlparse, ParseResult


def warn_future(message):
    warnings.warn(message, FutureWarning, stacklevel=2)


# ------------------------------------------------------------------------------

# defaults

MAX_FILEIZE = 2**19  # bytes; this is .5MB
MAX_CONNECTIONTIME = 20  # in seconds
DUMMY_URL = "http://example.com/index.html"

try:
    _compatible_sockets = (socket._socketobject, _socket.socket)
except AttributeError:
    # Fallback because socket._socketobject is not supported on some platforms.
    _compatible_sockets = _socket.socket

# ------------------------------------------------------------------------------

# regex library

RE_bad_title = re.compile(
    """(?:<title>|&lt;title&gt;)(.*)(?:<?/title>|(?:&lt;)?/title&gt;)""", re.I)


REGEX_doctype = re.compile("^\s*<!DOCTYPE[^>]*>", re.IGNORECASE)

RE_whitespace = re.compile("\s+")


PARSE_SAFE_FILES = ('html', 'txt', 'json', 'htm', 'xml',
                    'php', 'asp', 'aspx', 'ece', 'xhtml', 'cfm', 'cgi')

# based on DJANGO
# https://github.com/django/django/blob/master/django/core/validators.py
# not testing ipv6 right now, because rules are needed for ensuring they
# are correct
RE_VALID_HOSTNAME = re.compile(
    r'(?:'
        r'(?P<ipv4>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})'  # ...or ipv4
        r'|'
        #  r'(?P<ipv6>\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
        #  r'|'
        r'(?P<localhost>localhost)'  # localhost...
        r'|'
        r'(?P<domain>([A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}(?<!-)\.?))'  # domain...
        r'(?P<port>:\d+)?'  # optional port
    r')', re.IGNORECASE)


RE_PORT = re.compile(
    r'^'
    r'(?P<main>.+)'
    r':'
    r'(?P<port>\d+)'
    r'$', re.IGNORECASE
)


RE_DOMAIN_NAME = re.compile(
    r"""(^
            (?:
                [A-Z0-9]
                (?:
                    [A-Z0-9-]{0,61}
                    [A-Z0-9]
                )?
                \.
            )+
            (?:
                [A-Z]{2,6}\.?
                |
                [A-Z0-9-]{2,}
            (?<!-)\.?)
        $)""",
    re.VERBOSE | re.IGNORECASE)

RE_IPV4_ADDRESS = re.compile(
    r'^(\d{1,3})\.(\d{1,3}).(\d{1,3}).(\d{1,3})$'  # grab 4 octets
)

RE_ALL_NUMERIC = re.compile("^[\d\.]+$")


# ------------------------------------------------------------------------------


def is_parsed_valid_url(parsed, require_public_netloc=True, http_only=True):
    """returns bool
        `http_only`
            defaults True
            requires http or https for the scheme
    """
    assert isinstance(parsed, ParseResult)
    if __debug__:
        log.debug("is_parsed_valid_url = %s", parsed)
    if not all((parsed.scheme, parsed.netloc)):
        if __debug__:
            log.debug(" FALSE - missing `scheme` or `netloc`")
        return False
    if http_only:
        if parsed.scheme not in ('http', 'https'):
            if __debug__:
                log.debug(" FALSE - invalid `scheme`")
            return False
    if require_public_netloc:
        if __debug__:
            log.debug(" validating netloc")
        _netloc_match = RE_VALID_HOSTNAME.match(parsed.netloc)
        if not _netloc_match:
            if __debug__:
                log.debug(" did not match regex")
            return False

        # we may assign these
        _netloc_clean = parsed.netloc
        _port = None

        _netloc_ported = RE_PORT.match(parsed.netloc)
        if _netloc_ported:
            _netloc_ported_groudict = _netloc_ported.groupdict()
            _netloc_clean = _netloc_ported_groudict['main']
            _port = _netloc_ported_groudict['port']

        _netloc_groudict = _netloc_match.groupdict()
        if _netloc_groudict['ipv4'] is not None:
            octets = RE_IPV4_ADDRESS.match(_netloc_clean)
            if octets:
                if __debug__:
                    log.debug(" validating against ipv4")
                for g in octets.groups():
                    g = int(g)
                    if int(g) > 255:
                        if __debug__:
                            log.debug(" invalid ipv4; encountered an octect > 255")
                        return False
                if __debug__:
                    log.debug(" valid ipv4")
                return True
            if __debug__:
                log.debug(" invalid ipv4")
            return False
        else:
            if _netloc_clean == 'localhost':
                if __debug__:
                    log.debug(" localhost!")
                return True
            if RE_ALL_NUMERIC.match(_netloc_clean):
                if __debug__:
                    log.debug(" This only has numeric characters. "
                              "this is probably a fake or typo ip address.")
                return False
            if _port:
                try:
                    _port = int(_port)
                    if parsed.port != _port:
                        if __debug__:
                            log.debug(" netloc.port does not match our regex _port")
                        return False
                except:
                    if __debug__:
                        log.debug(" _port is not an int")
                    return False
            if RE_DOMAIN_NAME.match(_netloc_clean):
                if __debug__:
                    log.debug(" valid public domain name format")
                return True
        if __debug__:
            log.debug(" this appears to be invalid")
        return False
    return True


def is_parsed_valid_relative(parsed):
    """returns bool"""
    assert isinstance(parsed, ParseResult)
    if parsed.path and not any((parsed.scheme, parsed.hostname)):
        return True
    return False


def parsed_to_relative(parsed):
    """turns a parsed url into a full relative url"""
    assert isinstance(parsed, ParseResult)
    _path = parsed.path
    # cleanup, might be unnecessary now
    if _path and _path[0] != "/":
        # prepend a slash
        _path = "/%s" % _path
    if parsed.query:
        _path += "?" + parsed.query
    if parsed.fragment:
        _path += "#" + parsed.fragment
    return _path


def is_url_valid(url, require_public_netloc=None):
    """
    tries to parse a url. if valid returns `ParseResult`
    (boolean eval is True); if invalid returns `False`
    """
    if url is None:
        return False
    parsed = urlparse(url)
    if is_parsed_valid_url(parsed, require_public_netloc=require_public_netloc):
        return parsed
    return False


def url_to_absolute_url(url_test, url_fallback=None, require_public_netloc=None):
    """
        returns an "absolute url" if we have one.
        if we don't, it tries to fix the current url based on the fallback

        this shouldn't be needed, but it is.

        called by:

            MetadataParser.absolute_url()
            MetadataParser.get_discrete_url()

        args:
            `url_test` - the url to return/fix
            `url_fallback` - a fallback url.  this is returned in VERY bad
                errors. in "not so bad" errors, this is parsed and used as the
                base to construct a new url.
            `require_public_netloc` - requires the hostname/netloc to be a
                valid IPV4 or public dns domain name
    """
    if url_test is None and url_fallback is not None:
        return url_fallback

    parsed = urlparse(url_test)

    _path = parsed.path
    if _path:
        # sanity check
        # some stock plugins create invalid urls/files like '/...' in meta-data
        if _path[0] != "/":
            # prepend a slash
            _path = "/%s" % _path
        known_invalid_plugins = ['/...', ]
        if _path in known_invalid_plugins:
            return url_fallback

    # finally, fix the path
    # this isn't nested, because we could have kwargs
    _path = parsed_to_relative(parsed)

    if not _path:
        # so if our _path is BLANK, fuck it.
        # this can happen if someone puts in "" for the canonical
        return url_fallback

    rval = None

    # we'll use a placeholder for a source 'parsed' object that has a domain...
    parsed_domain_source = None

    # if we have a valid URL (OMFG, PLEASE)...
    if is_parsed_valid_url(parsed, require_public_netloc=require_public_netloc):
        parsed_domain_source = parsed
    else:
        # ok, the URL isn't valid
        # can we re-assemble it
        if url_fallback:
            parsed_fallback = urlparse(url_fallback)
            if is_parsed_valid_url(
                parsed_fallback,
                require_public_netloc=require_public_netloc
            ):
                parsed_domain_source = parsed_fallback
    if parsed_domain_source:
        rval = "%s://%s%s" % (
            parsed_domain_source.scheme,
            parsed_domain_source.netloc, _path)
    return rval


# ------------------------------------------------------------------------------


class InvalidDocument(Exception):

    def __init__(self, message=''):
        self.message = message

    def __str__(self):
        return "InvalidDocument: %s" % (self.message)


class NotParsable(Exception):

    def __init__(self, message='', raised=None, code=None):
        self.message = message
        self.raised = raised
        self.code = code

    def __str__(self):
        return "NotParsable: %s | %s | %s" % (self.message, self.code, self.raised)


class NotParsableFetchError(NotParsable):
    pass


class AllowableError(Exception):
    pass


class DummyResponse(object):
    """
    A DummyResponse is used to ensure compatibility between url fetching
    and html data
    """

    text = None
    url = None
    status_code = None
    encoding = None
    elapsed_seconds = None

    def __init__(
        self,
        text='',
        url=DUMMY_URL,
        status_code=200,
        encoding='utf-8',
        elapsed_seconds=0,
    ):
        self.text = text
        self.url = url
        self.status_code = status_code
        self.encoding = encoding
        self.elapsed = datetime.timedelta(0, elapsed_seconds)


# ------------------------------------------------------------------------------


def get_response_peername(r):
    if not isinstance(r, requests.models.Response):
        # raise AllowableError("Not a HTTPResponse")
        log.debug("Not a HTTPResponse | %s", r)
        return None

    def _get_socket():
        i = 0
        while True:
            i += 1
            try:
                if i == 1:
                    sock = r.raw._connection.sock
                elif i == 2:
                    sock = r.raw._connection.sock.socket
                elif i == 3:
                    sock = r.raw._fp.fp._sock
                elif i == 4:
                    sock = r.raw._fp.fp._sock.socket
                elif i == 5:
                    sock = r.raw._fp.fp.raw._sock
                else:
                    break
                if not isinstance(sock, _compatible_sockets):
                    raise AllowableError()
                return sock
            except Exception as e:
                pass
        return None
    sock = _get_socket()
    if sock:
        return sock.getpeername()
    return None


# ------------------------------------------------------------------------------


class MetadataParser(object):
    """
    turns text or a URL into a dict of dicts, extracting as much relevant
    metadata as possible.

    the 'keys' will be either the 'name' or 'property' attribute of the node.

    we EXPECT/REQUIRE a `head` in the document.

    the attribute's prefix are removed when storing into it's bucket
    eg:
        og:title -> 'og':{'title':''}

    metadata is stored into subgroups:

    page
        extracted from page elements
        saved into MetadataParser.metadata['page']
        example:
            <head><title>Awesome</title></head>
            MetadataParser.metadata = {'page': {'title':'Awesome'}}

    opengraph
        has 'og:' prefix
        saved into MetadataParser.metadata['og']
        example:
            <meta property="og:title" content="Awesome"/>
            MetadataParser.metadata = {'og': {'og:title':'Awesome'}}

    dublin core
        has 'dc:' prefix
        saved into MetadataParser.metadata['dc']
        example:
            <meta property="dc:title" content="Awesome"/>
            MetadataParser.metadata = {'dc': {'dc:title':'Awesome'}}

    meta
        has no prefix
        saved into MetadataParser.metadata['meta']
        example:
            <meta property="title" content="Awesome"/>
            MetadataParser.metadata = {'meta': {'dc:title':'Awesome'}}

    NOTE:
        passing in ssl_verify=False will turn off ssl verification checking
        in the requests library.
        this can be necessary on development machines
    """
    url = None
    url_actual = None
    strategy = None
    metadata = None
    LEN_MAX_TITLE = 255
    only_parse_file_extensions = None
    require_public_netloc = None
    force_doctype = None
    requests_timeout = None
    peername = None
    is_redirect = None
    is_redirect_same_host = None

    # allow for the beautiful_soup to be saved
    soup = None

    og_minimum_requirements = ['title', 'type', 'image', 'url']
    twitter_sections = ['card', 'title', 'site', 'description']
    strategy = ['og', 'dc', 'meta', 'page', 'twitter', ]

    def __init__(
        self,
        url=None, html=None, strategy=None, url_data=None, url_headers=None,
        force_parse=False, ssl_verify=True, only_parse_file_extensions=None,
        force_parse_invalid_content_type=False, require_public_netloc=True,
        force_doctype=False, requests_timeout=None, raise_on_invalid=False,
        search_head_only=None,
    ):
        """
        creates a new `MetadataParser` instance.

        kwargs:
            `url`
                url to parse
            `html`
                instead of a url, parse raw html
            `strategy`
                default: None
                sets default metadata strategy (['og', 'dc', 'meta', 'page'])
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
                set a list of valid file extensions.
                see `metadata_parser.PARSE_SAFE_FILES` for an example list
            `force_parse_invalid_content_type`
                default: False
                force parsing invalid content types
                by default this will only parse text/html content
            `require_public_netloc`
                default: True
                require a valid `netloc` for the host.  if `True`, valid hosts
                must be a properly formatted public domain name, IPV4 address
                or "localhost"
            `force_doctype`
                default: False
                if set to true, will replace a doctype with 'html'
                why? some cms give a bad doctype (like nasa.gov)
                which can break lxml/bsd
            `requests_timeout`
                default: None
                if set, proxies the value into `requests.get` as `timeout`
            `raise_on_invalid`
                default: False
                if True, will raise an InvalidDocument exception if the response
                does not look like a proper html document
            `search_head_only`
                default: None
                if `None` will default to True and emit a deprecation warning.
                if `True`, will only search the document head for meta information.
                `search_head_only=True` is the legacy behavior, but missed too many
                bad html implementations. This will be set to `False` in the future.
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
        self.soup = None
        self.force_doctype = force_doctype
        self.response = None
        self.response_headers = {}
        self.require_public_netloc = require_public_netloc
        self.requests_timeout = requests_timeout
        if search_head_only is None:
            warn_future("""`search_head_only` was not provided and defaulting to `True` """
                        """Future versions will default to `False`.""")
            search_head_only = True
        self.search_head_only = search_head_only
        self.raise_on_invalid = raise_on_invalid
        if only_parse_file_extensions is not None:
            self.only_parse_file_extensions = only_parse_file_extensions
        if html is None:
            html = self.fetch_url(
                url_data=url_data,
                url_headers=url_headers,
                force_parse=force_parse,
                force_parse_invalid_content_type=force_parse_invalid_content_type
            )
        else:
            self.response = DummyResponse(text=html, url=url or DUMMY_URL)
        self.parser(html, force_parse=force_parse)

    def is_opengraph_minimum(self):
        """
        returns true/false if the page has the minimum amount of opengraph tags
        """
        return all([hasattr(self, attr)
                   for attr in self.og_minimum_requirements])

    def fetch_url(
        self,
        url_data=None, url_headers=None, force_parse=False,
        force_parse_invalid_content_type=False
    ):
        """
        fetches the url and returns it.
        this was busted out so you could subclass.

        kwargs:
            url_data=None
            url_headers=None
            force_parse=False
            force_parse_invalid_content_type=False
        """
        # should we even download/parse this?
        if not force_parse and self.only_parse_file_extensions is not None:
            parsed = urlparse(self.url)
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

        # if someone does usertracking with sharethis.com, they get a hashbang
        # like this: http://example.com/page#.UHeGb2nuVo8
        # that fucks things up.
        url = self.url.split('#')[0]

        r = None
        try:
            # requests gives us unicode and the correct encoding, yay
            s = requests.Session()
            r = s.get(
                url, params=url_data, headers=url_headers,
                allow_redirects=True, verify=self.ssl_verify,
                timeout=self.requests_timeout, stream=True,
            )
            self.peername = get_response_peername(r)
            if r.history:
                self.is_redirect = True
                parsed_url_og = urlparse(url)
                parsed_url_dest = urlparse(r.url)
                self.is_redirect_same_host = True if (parsed_url_og.netloc == parsed_url_dest.netloc) else False

            content_type = None
            if 'content-type' in r.headers:
                content_type = r.headers['content-type']
                # content type can have a character encoding in it...
                content_type = [i.strip() for i in content_type.split(';')]
                content_type = content_type[0].lower()

            if (
                (
                    (content_type is None)
                    or
                    (content_type != 'text/html')
                )
                and
                (not force_parse_invalid_content_type)
            ):
                raise NotParsable("I don't know what type of file this is! "
                                  "content-type:'[%s]" % content_type)

            # okay, now we need to read
            html = r.text
            self.response = r

            # lowercase all of the HTTP headers for comparisons per RFC 2616
            self.response_headers = dict((k.lower(), v)
                                         for k, v in r.headers.items())
            self.url_actual = r.url
            if r.status_code != 200:
                raise NotParsableFetchError(
                    message="Status Code is not 200",
                    code=r.status_code
                )

        except requests.exceptions.RequestException as error:
            raise NotParsableFetchError(
                message="Error with `requests` library.  Inspect the `raised`"
                        " attribute of this error.",
                raised=error
            )

        return html

    def absolute_url(self, link=None):
        """
        makes the url of a submitted `link` absolute,
        as sometimes people use a relative url. sigh.
        kwargs:
            link=None
        """
        url_fallback = self.url_actual or self.url or None
        return url_to_absolute_url(
            link,
            url_fallback=url_fallback,
            require_public_netloc=self.require_public_netloc
        )

    def parser(self, html, force_parse=False):
        """
        parses submitted `html`

        args:
            html

        kwargs:
            force_parse=False
        """
        if not isinstance(html, BeautifulSoup):
            # clean the html?
            if self.force_doctype:
                html = REGEX_doctype.sub("<!DOCTYPE html>", html)
            try:
                doc = BeautifulSoup(html, "lxml")
            except:
                doc = BeautifulSoup(html, "html.parser")
        else:
            doc = html

        # let's ensure that we have a real document...
        if not doc or not doc.html:
            if self.raise_on_invalid:
                raise InvalidDocument("missing `doc` or `doc.html`")
            return

        # set the searchpath
        doc_searchpath = doc.html

        if self.search_head_only:
            if not doc.html.head:
                if self.raise_on_invalid:
                    raise InvalidDocument("missing `doc.html.head`")
                return
            doc_searchpath = doc.html.head

        # stash the bs4 doc for further operations
        self.soup = doc

        ogs = doc_searchpath.findAll(
            'meta',
            attrs={'property': re.compile(r'^og')}
        )
        for og in ogs:
            try:
                self.metadata['og'][og['property'][3:]] = og['content'].strip()
            except (AttributeError, KeyError):
                pass
            except:
                if __debug__:
                    log.debug("Ran into a serious error parsing `og`")
                pass

        twitters = doc_searchpath.findAll(
            'meta',
            attrs={'name': re.compile(r'^twitter')}
        )
        for twitter in twitters:
            try:
                self.metadata['twitter'][
                    twitter['name'][8:]] = twitter['value'].strip()
            except (AttributeError, KeyError):
                pass

        # pull the text off the title
        try:
            _title_text = doc_searchpath.title.text
            if _title_text is not None:
                _title_text = _title_text.strip()
            if len(_title_text) > self.LEN_MAX_TITLE:
                _title_text = _title_text[:self.LEN_MAX_TITLE]
            self.metadata['page']['title'] = _title_text
        except AttributeError:
            pass

        # is there an image_src?
        images = doc.findAll(
            'link',
            attrs={'rel': re.compile("^image_src$", re.I)}
        )
        if images:
            image = images[0]
            if image.has_attr("href"):
                img_url = image['href'].strip()
                self.metadata['page']['image'] = img_url
            elif image.has_attr("content"):
                img_url = image['content'].strip()
                self.metadata['page']['image'] = img_url
            else:
                pass

        # figure out the canonical url
        canonicals = doc.findAll(
            'link',
            attrs={'rel': re.compile("^canonical$", re.I)}
        )
        if canonicals:
            canonical = canonicals[0]
            if canonical.has_attr("href"):
                link = canonical['href'].strip()
                self.metadata['page']['canonical'] = link
            elif canonical.has_attr("content"):
                link = canonical['content'].strip()
                self.metadata['page']['canonical'] = link
            else:
                pass

        # pull out all the metadata
        meta = doc_searchpath.findAll(name='meta')
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
        """
        looks for the field in various stores.  defaults to the core
        strategy, though you may specify a certain item.  if you search for
        'all' it will return a dict of all values.

        args:
            field

        kwargs:
            strategy=None
                ('all') or iterable ['og', 'dc', 'meta', 'page', 'twitter', ]
        """
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

    def get_discrete_url(
        self,
        og_first=True, canonical_first=False, allow_invalid=False
    ):
        """
        convenience method.
        if `allow_invalid` is True, it will return the raw data.
        if `allow_invalid` is False (default), it will try to correct
            the data (relative to absolute) or reset to None.

        kwargs:
            og_first=True
            canonical_first=False
            allow_invalid=False
        """
        og = self.get_metadata('url', strategy=['og'])
        canonical = self.get_metadata('canonical', strategy=['page'])

        if not allow_invalid:

            # fallback url is used to drop a domain
            url_fallback = self.url_actual or self.url or None

            if og and not is_url_valid(
                og,
                require_public_netloc=self.require_public_netloc
            ):
                # try making it absolute
                og = url_to_absolute_url(
                    og,
                    url_fallback=url_fallback,
                    require_public_netloc=self.require_public_netloc
                )
                if not is_url_valid(
                    og,
                    require_public_netloc=self.require_public_netloc
                ):
                    # set to NONE if invalid
                    og = None

            if canonical and not is_url_valid(
                canonical,
                require_public_netloc=self.require_public_netloc
            ):
                # try making it absolute
                canonical = url_to_absolute_url(
                    canonical,
                    url_fallback=url_fallback,
                    require_public_netloc=self.require_public_netloc
                )
                if not is_url_valid(
                    canonical,
                    require_public_netloc=self.require_public_netloc
                ):
                    # set to NONE if invalid
                    canonical = None

        rval = []
        if og_first:
            rval = (og, canonical)
        elif canonical_first:
            rval = (canonical, og)

        for i in rval:
            if i:
                return i

        return self.absolute_url()

    def get_metadata_link(self, field, strategy=None, allow_encoded_uri=False):
        """sometimes links are bad; this tries to fix them.  most useful for meta images

        args:
            field

        kwargs:
            strategy=None
                ('all') or iterable ['og', 'dc', 'meta', 'page', 'twitter', ]
            allow_encoded_uri
        """
        # `_value` will be our raw value
        _value = self.get_metadata(field, strategy=strategy)
        if not _value:
            return None

        # `value` will be our clean value
        # remove whitespace, because some bad blogging platforms add in whitespace by printing elements on multiple lines. d'oh!
        value = RE_whitespace.sub('', _value)

        # it's possible for an encoded URI to be an image
        # if that is the case, don't return it (this is `get_metadata_LINK`)
        if value.lower().startswith('data:image/'):
            if allow_encoded_uri:
                return value
            return None

        # if the url is valid, RETURN IT
        if is_url_valid(value, require_public_netloc=self.require_public_netloc):
            return value

        # fallback url is used to drop a domain
        url_fallback = self.url_actual or self.url or None

        # try making it absolute
        value_fixed = url_to_absolute_url(
            value,
            url_fallback=url_fallback,
            require_public_netloc=self.require_public_netloc
        )
        if is_url_valid(value_fixed, require_public_netloc=self.require_public_netloc):
            return value_fixed

        return None
