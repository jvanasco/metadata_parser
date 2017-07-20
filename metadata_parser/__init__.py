import logging
log = logging.getLogger(__name__)


# ------------------------------------------------------------------------------


__VERSION__ = '0.9.12'


# ------------------------------------------------------------------------------


# stdlib
import datetime
import re
import unicodedata
import warnings
import pdb

# pypi
import requests
from bs4 import BeautifulSoup

try:
    import tldextract
    USE_TLDEXTRACT = True
except:
    USE_TLDEXTRACT = False

# python 2/3
try:
    # Python 2 has a standard urlparse library
    from urlparse import urlparse, ParseResult
except:
    # Python 3 has the same library hidden in urllib.parse
    from urllib.parse import urlparse, ParseResult
import sys
PY3 = sys.version_info[0] == 3


def warn_future(message):
    warnings.warn(message, FutureWarning, stacklevel=2)


# ------------------------------------------------------------------------------

# defaults

MAX_FILEIZE = 2**19  # bytes; this is .5MB
MAX_CONNECTIONTIME = 20  # in seconds
DUMMY_URL = "http://example.com/index.html"

# peername hacks
# these are in the stdlib
# will be eventually not be needed thanks to upstream changes in `requests`
import _socket
import socket
try:
    _compatible_sockets = (_socket.socket, socket._socketobject, )
except AttributeError:
    _compatible_sockets = (_socket.socket, )

# ------------------------------------------------------------------------------

# regex library

RE_bad_title = re.compile(
    """(?:<title>|&lt;title&gt;)(.*)(?:<?/title>|(?:&lt;)?/title&gt;)""", re.I)


REGEX_doctype = re.compile("^\s*<!DOCTYPE[^>]*>", re.IGNORECASE)

RE_whitespace = re.compile("\s+")


PARSE_SAFE_FILES = ('html', 'txt', 'json', 'htm', 'xml',
                    'php', 'asp', 'aspx', 'ece', 'xhtml', 'cfm', 'cgi')

RE_prefix_opengraph = re.compile(r'^og')
RE_prefix_twitter = re.compile(r'^twitter')
RE_prefix_rel_img_src = re.compile("^image_src$", re.I)
RE_canonical = re.compile("^canonical$", re.I)
RE_shortlink = re.compile("^shortlink$", re.I)

# based on DJANGO
# https://github.com/django/django/blob/master/django/core/validators.py
# not testing ipv6 right now, because rules are needed for ensuring they
# are correct
RE_VALID_NETLOC = re.compile(
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


# these aren't on the public internet
PRIVATE_HOSTNAMES = ('localhost',
                     '127.0.0.1',
                     '0.0.0.0',
                     )


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

# we may need to test general validity of url components
RE_rfc3986_valid_characters = re.compile("""^[a-z0-9\-\.\_\~\:\/\?\#\[\]\@\!\$\&\'\(\)\*\+\,\;\=\%]+$""", re.I)
"""
What is valid in the RFC?
    # don't need escaping
    rfc3986_unreserved__noescape = ['a-z', '0-9', ]  
    
    # do need escaping
    rfc3986_unreserved__escape = ['-', '.', '_', '~', ]
    rfc3986_gen_delims__escape = [":", "/", "?", "#", "[", "]", "@", ]
    rfc3986_sub_delims__escape = ["!", "$", "&", "'", "(", ")", "*", "+", ",", ";", "=", ]
    rfc3986_pct_encoded__escape = ["%", ]
    rfc3986__escape = rfc3986_unreserved__escape  + rfc3986_gen_delims__escape + rfc3986_sub_delims__escape + rfc3986_pct_encoded__escape
    rfc3986__escaped = re.escape(''.join(rfc3986__escape))
    rfc3986_chars = ''.join(rfc3986_unreserved__noescape) + rfc3986__escaped
    print rfc3986_chars

    a-z0-9\-\.\_\~\:\/\?\#\[\]\@\!\$\&\'\(\)\*\+\,\;\=\%
"""
    

# ------------------------------------------------------------------------------


def encode_ascii(text):
    """
    helper function to force ascii; some edge-cases have unicode line breaks in titles/etc.
    """
    if not text:
        text = ''
    if not PY3:
        text = unicode(text)
    normalized = unicodedata.normalize('NFKD', text).encode('ascii', 'ignore')
    if PY3:
        normalized = normalized.decode("utf-8", "ignore")
    return normalized


# ------------------------------------------------------------------------------


def is_hostname_valid(hostname, allow_localhosts=True, require_public_netloc=False):
    if hostname.lower() in PRIVATE_HOSTNAMES:
        if not allow_localhosts:
            return False
        if require_public_netloc:
            return False
        return True
    if USE_TLDEXTRACT:
        extracted = tldextract.extract(hostname)
        if not extracted.registered_domain:
            return False
        return True
    if RE_DOMAIN_NAME.match(hostname):
        return True
    return False


def is_parsed_valid_url(
    parsed,
    require_public_netloc=True,
    allow_localhosts=True,
    http_only=True
):
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
        _netloc_match = RE_VALID_NETLOC.match(parsed.netloc)
        if not _netloc_match:
            if __debug__:
                log.debug(" did not match regex")
            return False

        # we may assign these
        _hostname = parsed.hostname
        _port = parsed.port

        # this can be a fast check..
        # note this is done AFTER we clean up a potential port grouping
        if __debug__:
            log.debug(" validating against PRIVATE_HOSTNAMES")
        if _hostname.lower() in PRIVATE_HOSTNAMES:
            if __debug__:
                log.debug(" matched PRIVATE_HOSTNAMES")
            if allow_localhosts:
                return True
            return False

        _netloc_groudict = _netloc_match.groupdict()
        if _netloc_groudict['ipv4'] is not None:
            octets = RE_IPV4_ADDRESS.match(_hostname)
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
            if _hostname == 'localhost':
                if __debug__:
                    log.debug(" localhost!")
                return False
            if RE_ALL_NUMERIC.match(_hostname):
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
            if USE_TLDEXTRACT:
                _extracted = tldextract.extract(_hostname)
                if not _extracted.registered_domain:
                    return False
                return True
            if RE_DOMAIN_NAME.match(_hostname):
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


def parsed_to_relative(parsed, parsed_fallback=None):
    """turns a parsed url into a full relative path"""
    assert isinstance(parsed, ParseResult)
    _path = parsed.path
    # cleanup, might be unnecessary now
    if _path and _path[0] != "/":
        if parsed_fallback:
            assert isinstance(parsed_fallback, ParseResult)
            _path_fallback = parsed_fallback.path
            if _path_fallback and _path_fallback[0] != '/':
                # there's not much we can do here... pretend there's no fallback
                _path = "/%s" % _path
            else:
                _path_fallback_dir = '/'.join(_path_fallback.split('/')[:-1])
                _path = "%s/%s" % (_path_fallback_dir, _path)
        else:
            # prepend a slash
            _path = "/%s" % _path
    if parsed.query:
        _path += "?" + parsed.query
    if parsed.fragment:
        _path += "#" + parsed.fragment
    return _path


def is_url_valid(
    url,
    require_public_netloc=None,
    allow_localhosts=None,
):
    """
    tries to parse a url. if valid returns `ParseResult`
    (boolean eval is True); if invalid returns `False`
    """
    if url is None:
        return False
    parsed = urlparse(url)
    if is_parsed_valid_url(
        parsed,
        require_public_netloc=require_public_netloc,
        allow_localhosts=allow_localhosts,
    ):
        return parsed
    return False


def url_to_absolute_url(
    url_test,
    url_fallback=None,
    require_public_netloc=None,
    allow_localhosts=None,
):
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
        `allow_localhosts` - filters localhost values
    """
    # quickly correct for some dumb mistakes
    if isinstance(url_test, str):
        if url_test.lower() in ("http://", "https://"):
            url_test = None

    # if we don't have a test url or fallback, we can't generate an absolute
    if not url_test and not url_fallback:
        return None

    if url_test is None and url_fallback is not None:
        return url_fallback

    parsed = urlparse(url_test)
    
    # if we passed in a url, we can't remount it onto another domain
    if parsed.hostname:
        if not is_hostname_valid(parsed.hostname, allow_localhosts=True):
            return None

    _path = parsed.path
    if _path:
        # sanity check
        # some stock plugins create invalid urls/files like '/...' in meta-data
        known_invalid_plugins_paths = ['/...', ]
        if _path[0] != "/":
            # prepend a slash
            _path = "/%s" % _path
        if _path in known_invalid_plugins_paths:
            return url_fallback

    parsed_fallback = urlparse(url_fallback)

    """
    # this was a testing concept to remount the path
    # not needed currently
    if _path != parsed.path:
        parsed = ParseResult(parsed.scheme, parsed.netloc, _path, parsed.params, parsed.query, parsed.fragment)
    """

    # finally, fix the path
    # this isn't nested, because we could have kwargs
    _path = parsed_to_relative(parsed, parsed_fallback=parsed_fallback)
    if not _path:
        # so if our _path is BLANK, we may want to say "fuck this"
        # this can happen if someone puts in "" for the canonical
        # but this can also happen if we have different domains...
        if url_fallback:
            if (parsed_fallback.scheme == parsed.scheme) or (parsed_fallback.netloc == parsed.netloc):
                return url_fallback

    rval = None

    # we'll use a placeholder for a source 'parsed' object that has a domain...
    parsed_domain_source = None

    # if we have a valid URL (OMFG, PLEASE)...
    if is_parsed_valid_url(
        parsed,
        require_public_netloc=require_public_netloc,
        allow_localhosts=allow_localhosts,
    ):
        parsed_domain_source = parsed
    else:
        # ok, the URL isn't valid
        # can we re-assemble it
        if url_fallback:
            if is_parsed_valid_url(
                parsed_fallback,
                require_public_netloc=require_public_netloc,
                allow_localhosts=allow_localhosts,
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

    def __init__(self, message='', raised=None, code=None, metadataParser=None):
        self.message = message
        self.raised = raised
        self.code = code
        self.metadataParser = metadataParser

    def __str__(self):
        return "NotParsable: %s | %s | %s" % (self.message, self.code, self.raised)


class NotParsableJson(NotParsable):

    def __str__(self):
        return "NotParsableJson: %s | %s | %s" % (self.message, self.code, self.raised)


class NotParsableRedirect(NotParsable):
    """Raised if a redirect is detected, but there is no Location header."""
    def __str__(self):
        return "NotParsableRedirect: %s | %s | %s" % (self.message, self.code, self.raised)


class NotParsableFetchError(NotParsable):
    def __str__(self):
        return "NotParsableFetchError: %s | %s | %s" % (self.message, self.code, self.raised)


class AllowableError(Exception):
    pass


class RedirectDetected(Exception):
    """
    Raised if a redirect is detected
    Instance properties:

    ``location``: redirect location
    ``code``: status code of the response
    ``response``: actual response object
    """
    def __init__(self, location='', code=None, response=None, metadataParser=None):
        self.location = location
        self.code = code
        self.response = response
        self.metadataParser = metadataParser


# ------------------------------------------------------------------------------


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
    history = None
    headers = None
    content = None

    def __init__(
        self,
        text='',
        url=DUMMY_URL,
        status_code=200,
        encoding='utf-8',
        elapsed_seconds=0,
        headers=None,
        content=None,
    ):
        self.text = text
        self.url = url
        self.status_code = status_code
        self.encoding = encoding
        self.elapsed = datetime.timedelta(0, elapsed_seconds)
        self.headers = headers if headers is not None else {}
        self.content = content


# ------------------------------------------------------------------------------


def get_response_peername(r):
    """
    used to get the peername (ip+port) data from the request
    if a socket is found, caches this onto the request object
    """
    if not isinstance(r, requests.models.Response):
        # raise AllowableError("Not a HTTPResponse")
        log.debug("Not a HTTPResponse | %s", r)
        return None

    if hasattr(r, '_mp_peername'):
        return r._mp_peername

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
            except Exception as e:  # noqa
                pass
        return None

    sock = _get_socket()
    if sock:
        # only cache if we have a sock
        # we may want/need to call again
        r._mp_peername = sock.getpeername()
        return r._mp_peername
    return None


# ------------------------------------------------------------------------------


class ParsedResult(object):
    metadata = None
    soup = None

    og_minimum_requirements = ['title', 'type', 'image', 'url']
    twitter_sections = ['card', 'title', 'site', 'description']
    strategy = ['og', 'dc', 'meta', 'page', 'twitter', ]

    def __init__(self):
        self.metadata = {
            'og': {},
            'meta': {},
            'dc': {},
            'page': {},
            'twitter': {},
            '_internal': {},
        }

    def get_metadata(self, field, strategy=None, encoder=None):
        """
        looks for the field in various stores.  defaults to the core
        strategy, though you may specify a certain item.  if you search for
        'all' it will return a dict of all values.

        args:
            field

        kwargs:
            strategy=None
                ('all') or iterable ['og', 'dc', 'meta', 'page', 'twitter', ]
            encoder=None
                a function, such as `encode_ascii`, to encode values.
                a valid `encoder` accepts one(1) arg.
        """
        if strategy:
            _strategy = strategy
        else:
            _strategy = self.strategy
        if _strategy == 'all':
            rval = {}
            for store in self.metadata:
                if field in self.metadata[store]:
                    val = self.metadata[store][field]
                    if encoder:
                        val = encoder(val)
                    rval[store] = val
            return rval
        for store in _strategy:
            if store in self.metadata:
                if field in self.metadata[store]:
                    val = self.metadata[store][field]
                    if encoder:
                        val = encoder(val)
                    return val
        return None

    def is_opengraph_minimum(self):
        """
        returns true/false if the page has the minimum amount of opengraph tags
        """
        return all([self.metadata['og'].get(attr, None) for attr in self.og_minimum_requirements])


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
    LEN_MAX_TITLE = 255
    only_parse_file_extensions = None
    allow_localhosts = None
    require_public_netloc = None
    force_doctype = None
    requests_timeout = None
    peername = None
    is_redirect = None
    is_redirect_unique = None
    is_redirect_same_host = None

    force_parse = None
    force_parse_invalid_content_type = None
    only_parse_http_ok = None
    requests_session = None

    # allow for the beautiful_soup to be saved
    soup = None

    def __init__(
        self,
        url=None, html=None, strategy=None, url_data=None, url_headers=None,
        force_parse=False, ssl_verify=True, only_parse_file_extensions=None,
        force_parse_invalid_content_type=False, require_public_netloc=True,
        allow_localhosts=None, force_doctype=False, requests_timeout=None,
        raise_on_invalid=False, search_head_only=None, allow_redirects=True,
        requests_session=None, only_parse_http_ok=True, defer_fetch=False,
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
                sets .force_parse
            `force_parse_invalid_content_type`
                default: False
                force parsing invalid content types
                by default this will only parse text/html content
                sets .force_parse_invalid_content_type
            `ssl_verify`
                default: True
                disable ssl verification, sometimes needed in development
            `only_parse_file_extensions`
                default: None
                set a list of valid file extensions.
                see `metadata_parser.PARSE_SAFE_FILES` for an example list
            `require_public_netloc`
                default: True
                require a valid `netloc` for the host.  if `True`, valid hosts
                must be a properly formatted public domain name, IPV4 address
                or "localhost"
            `allow_localhosts`
                default: True
                If True, `localhost`, '127.0.0.1`, and `0.0.0.0` values will be
                valid.
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
            `allow_redirects`
                default: True
                passed onto `fetch_url`, which will pass it onto requests.get
            `requests_session`
                default: None
                passed onto `fetch_url`, which will utilize it.
                an instance of `requests.Session` or a subclass
            `only_parse_http_ok`
                default: True
                used by `fetch_url`
            `defer_fetch`:
                default: False
                if True, will not fetch the url.
        """
        if url is not None:
            url = url.strip()
        self.parsed_result = ParsedResult()
        if strategy:
            self.parsed_result.strategy = strategy
        self.url = self.parsed_result.metadata['_internal']['url'] = url
        self.url_actual = self.parsed_result.metadata['_internal']['url_actual'] = url
        self.ssl_verify = ssl_verify
        self.force_doctype = force_doctype
        self.response = None
        self.response_headers = {}
        self.require_public_netloc = require_public_netloc
        self.allow_localhosts = allow_localhosts
        self.requests_timeout = requests_timeout
        self.allow_redirects = allow_redirects
        self.force_parse = force_parse
        self.force_parse_invalid_content_type = force_parse_invalid_content_type
        self.only_parse_http_ok = only_parse_http_ok
        if search_head_only is None:
            warn_future("""`search_head_only` was not provided and defaulting to `True` """
                        """Future versions will default to `False`.""")
            search_head_only = True
        self.search_head_only = search_head_only
        self.raise_on_invalid = raise_on_invalid
        self.requests_session = requests_session
        if only_parse_file_extensions is not None:
            self.only_parse_file_extensions = only_parse_file_extensions
        if html is None:
            # we may not have a url for tests or other api usage
            if url:
                if defer_fetch:
                    def deferred_fetch():
                        html = self.fetch_url(url_data=url_data,
                                              url_headers=url_headers,
                                              )
                        self.parse(html)
                        return
                    self.deferred_fetch = deferred_fetch
                    return
                html = self.fetch_url(url_data=url_data,
                                      url_headers=url_headers,
                                      )
            else:
                html = ''
        else:
            self.response = DummyResponse(text=html, url=url or DUMMY_URL)
        if html:
            self.parse(html)

    # --------------------------------------------------------------------------

    @property
    def metadata(self):
        # deprecating in 1.0
        return self.parsed_result.metadata

    @property
    def soup(self):
        # deprecating in 1.0
        return self.parsed_result.soup

    def get_metadata(self, field, strategy=None, encoder=None):
        # deprecating in 1.0
        return self.parsed_result.get_metadata(field, strategy=strategy, encoder=encoder)

    def is_opengraph_minimum(self):
        # deprecating in 1.0
        return self.parsed_result.is_opengraph_minimum()

    # --------------------------------------------------------------------------

    def deferred_fetch(self):
        # allows for a deferrable fetch; override in __init__
        raise ValueError("no `deferred_fetch` set")

    # --------------------------------------------------------------------------

    def fetch_url(
        self,
        url_data=None, url_headers=None, force_parse=None,
        force_parse_invalid_content_type=None, allow_redirects=None,
        ssl_verify=None, requests_timeout=None, requests_session=None,
        only_parse_http_ok=None,
    ):
        """
        fetches the url and returns it.
        this was busted out so you could subclass.

        kwargs:
            url_data=None
            url_headers=None
            force_parse=None
                defaults to self.force_parse if None
            force_parse_invalid_content_type=None
                defaults to self.force_parse if None
            only_parse_http_ok=None
                defaults to self.only_parse_http_ok if None
            ssl_verify = None
                defaults to self.ssl_verify if None
                passed onto `requests.get`
            allow_redirects=None
                defaults to self.allow_redirects if None
                passed onto `requests.get`
            requests_timeout=None
                defaults to self.requests_timeout if None
                passed onto `requests.get`
            requests_session=None
                defaults to self.requests_session if None
                an instance of `requests.Session` or a subclass
                if `None`, will create a new Session.
        """
        # should we even download/parse this?
        force_parse = force_parse if force_parse is not None else self.force_parse
        force_parse_invalid_content_type = force_parse_invalid_content_type if force_parse_invalid_content_type is not None else self.force_parse_invalid_content_type
        only_parse_http_ok = only_parse_http_ok if only_parse_http_ok is not None else self.only_parse_http_ok
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
                        raise NotParsable("I don't know what this file is", metadataParser=self)

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
            allow_redirects = allow_redirects if allow_redirects is not None else self.allow_redirects
            requests_timeout = requests_timeout if requests_timeout is not None else self.requests_timeout
            ssl_verify = ssl_verify if ssl_verify is not None else self.ssl_verify
            requests_session = requests_session if requests_session is not None else self.requests_session
            if requests_session is None:
                requests_session = requests.Session()
            r = requests_session.get(
                url, params=url_data, headers=url_headers,
                allow_redirects=allow_redirects, verify=ssl_verify,
                timeout=requests_timeout, stream=True,
            )
            self.response = r
            self.peername = get_response_peername(r)
            if r.history:
                self.is_redirect = True
                # sometimes we encounter a circular redirect for auth
                self.is_redirect_unique = False if r.url == r.history[0].url else True
                parsed_url_og = urlparse(url)
                parsed_url_dest = urlparse(r.url)
                self.is_redirect_same_host = True if (parsed_url_og.netloc == parsed_url_dest.netloc) else False
            else:
                self.is_redirect = False
                self.is_redirect_unique = False

            # lowercase all of the HTTP headers for comparisons per RFC 2616
            self.response_headers = dict((k.lower(), v)
                                         for k, v in r.headers.items())
            # stash this into the url actual too
            self.url_actual = self.parsed_result.metadata['_internal']['url_actual'] = r.url

            # if we're not following redirects, there could be an error here!
            if not allow_redirects:
                if r.status_code in (301, 302, 307, 308):
                    header_location = r.headers.get('location')
                    if header_location:
                        raise RedirectDetected(location=header_location,
                                               code=r.status_code,
                                               response=r,
                                               metadataParser=self,
                                               )
                    raise NotParsableRedirect(
                        message="Status Code is redirect, but missing header",
                        code=r.status_code,
                        metadataParser=self,
                    )

            if only_parse_http_ok and r.status_code != 200:
                raise NotParsableFetchError(
                    message="Status Code is not 200",
                    code=r.status_code,
                    metadataParser=self,
                )

            content_type = None
            if 'content-type' in r.headers:
                content_type = r.headers['content-type']
                # content type can have a character encoding in it...
                content_type = [i.strip() for i in content_type.split(';')]
                content_type = content_type[0].lower()
                if content_type == 'application/json':
                    raise NotParsableJson("JSON header detected",
                                          metadataParser=self)
            if (((content_type is None) or (content_type != 'text/html'))
                and
                (not force_parse_invalid_content_type)
            ):
                raise NotParsable("I don't know what type of file this is! "
                                  "content-type:'[%s]" % content_type,
                                  metadataParser=self)

            # okay, now we're safe to consume the request content
            html = r.text

        except requests.exceptions.RequestException as error:
            if hasattr(error, 'response') and (error.response is not None):
                self.response = error.response
                try:
                    self.peername = get_response_peername(self.response)
                    if self.response.history:
                        self.is_redirect = True
                except:
                    pass
            raise NotParsableFetchError(
                message="Error with `requests` library.  Inspect the `raised`"
                        " attribute of this error.",
                raised=error,
                metadataParser=self,
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
            require_public_netloc=self.require_public_netloc,
            allow_localhosts=self.allow_localhosts,
        )

    def parse(self, html):
        """
        parses submitted `html`

        args:
            html
        """
        if not isinstance(html, BeautifulSoup):
            # clean the html?
            if self.force_doctype:
                html = REGEX_doctype.sub("<!DOCTYPE html>", html)
            try:
                try:
                    doc = BeautifulSoup(html, "lxml")
                except:
                    doc = BeautifulSoup(html, "html.parser")
            except:
                raise NotParsable("could not parse into BeautifulSoup",
                                  metadataParser=self)
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
        self.parsed_result.soup = doc

        ogs = doc_searchpath.findAll('meta',
                                     attrs={'property': RE_prefix_opengraph, }
                                     )
        for og in ogs:
            try:
                self.parsed_result.metadata['og'][og['property'][3:]] = og['content'].strip()
            except (AttributeError, KeyError):
                pass
            except:
                if __debug__:
                    log.debug("Ran into a serious error parsing `og`")
                pass

        twitters = doc_searchpath.findAll('meta',
                                          attrs={'name': RE_prefix_twitter, }
                                          )
        for twitter in twitters:
            try:
                self.parsed_result.metadata['twitter'][
                    twitter['name'][8:]] = twitter['content'].strip()
            except (AttributeError, KeyError):
                pass

        # pull the text off the title
        try:
            _title_text = doc_searchpath.title.text
            if _title_text is not None:
                _title_text = _title_text.strip()
            if len(_title_text) > self.LEN_MAX_TITLE:
                _title_text = _title_text[:self.LEN_MAX_TITLE]
            self.parsed_result.metadata['page']['title'] = _title_text
        except AttributeError:
            pass

        # is there an image_src?
        images = doc.findAll('link',
                             attrs={'rel': RE_prefix_rel_img_src, }
                             )
        if images:
            image = images[0]
            if image.has_attr("href"):
                img_url = image['href'].strip()
                self.parsed_result.metadata['page']['image'] = img_url
            elif image.has_attr("content"):
                img_url = image['content'].strip()
                self.parsed_result.metadata['page']['image'] = img_url
            else:
                pass

        # figure out the canonical url
        canonicals = doc.findAll('link',
                                 attrs={'rel': RE_canonical, }
                                 )
        if canonicals:
            canonical = canonicals[0]
            if canonical.has_attr("href"):
                link = canonical['href'].strip()
                self.parsed_result.metadata['page']['canonical'] = link
            elif canonical.has_attr("content"):
                link = canonical['content'].strip()
                self.parsed_result.metadata['page']['canonical'] = link
            else:
                pass

        # is there a shortlink?
        shortlinks = doc.findAll('link',
                                 attrs={'rel': RE_shortlink}
                                 )
        if shortlinks:
            shortlink = shortlinks[0]
            if shortlink.has_attr("href"):
                link = shortlink['href'].strip()
                self.parsed_result.metadata['page']['shortlink'] = link
            elif shortlink.has_attr("content"):
                link = shortlink['content'].strip()
                self.parsed_result.metadata['page']['shortlink'] = link
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
                        self.parsed_result.metadata['dc'][k[3:]] = v
                    else:
                        self.parsed_result.metadata['meta'][k] = v
            except AttributeError:
                pass

    def get_fallback_url(
        self,
        require_public_netloc=True,
        allow_localhosts=True,
    ):
        for _fallback_candndiate in (self.url_actual, self.url):
            if not _fallback_candndiate:
                continue
            if require_public_netloc or allow_localhosts:
                _parsed = is_url_valid(_fallback_candndiate,
                                       require_public_netloc=require_public_netloc,
                                       allow_localhosts=allow_localhosts,
                                       )
                if not _parsed:
                    continue
            # okay this works
            return _fallback_candndiate
        return None

    # --------------------------------------------------------------------------

    def get_url_canonical(
        self,
        require_public_global=True,
        url_fallback=None,
    ):
        """this was originally part of `get_discrete_url`"""
        canonical = self.get_metadata('canonical', strategy=['page'])
        if not canonical:
            return None
        # does the canonical have valid characters?
        # some websites, even BIG PROFESSIONAL ONES, will put html in here.
        # amateurs.
        canonical_valid_chars = RE_rfc3986_valid_characters.match(canonical)
        if not canonical_valid_chars:
            return None
        if require_public_global:
            if url_fallback is None:
                # derive a fallback url, and ensure it is valid
                url_fallback = self.get_fallback_url(require_public_netloc=True,
                                                     allow_localhosts=False,
                                                     )
            if canonical and not is_url_valid(
                canonical,
                require_public_netloc=True,
                allow_localhosts=False,
            ):
                # try making it absolute
                
                
                canonical = url_to_absolute_url(
                    canonical,
                    url_fallback=url_fallback,
                    require_public_netloc=True,
                    allow_localhosts=False,
                )
                if not is_url_valid(
                    canonical,
                    require_public_netloc=True,
                    allow_localhosts=False,
                ):
                    # set to NONE if invalid
                    canonical = None
        return canonical

    def get_url_opengraph(
        self,
        require_public_global=True,
        url_fallback=None,
    ):
        """this was originally part of `get_discrete_url`"""
        og = self.get_metadata('url', strategy=['og'])
        if not og:
            return None
        # does the og have valid characters?
        # some websites, even BIG PROFESSIONAL ONES, will put html in here.
        # idiots.
        og_valid_chars = RE_rfc3986_valid_characters.match(og)
        if not og_valid_chars:
            return None
        if require_public_global:
            if url_fallback is None:
                # derive a fallback url, and ensure it is valid
                url_fallback = self.get_fallback_url(require_public_netloc=True,
                                                     allow_localhosts=False,
                                                     )
            if og and not is_url_valid(
                og,
                require_public_netloc=True,
                allow_localhosts=False,
            ):
                # try making it absolute
                og = url_to_absolute_url(
                    og,
                    url_fallback=url_fallback,
                    require_public_netloc=True,
                    allow_localhosts=False,
                )
                if not is_url_valid(
                    og,
                    require_public_netloc=True,
                    allow_localhosts=False,
                ):
                    # set to NONE if invalid
                    og = None
        return og

    # --------------------------------------------------------------------------

    def get_discrete_url(
        self,
        og_first=True,
        canonical_first=False,
        require_public_global=True,
    ):
        """
        convenience method.
        if `require_public_global` is True, it will try to correct
            the data (relative to absolute) or reset to None.  This option will
            also require the fallback url to be on the public internet and not
            be a localhost value.

        kwargs:
            og_first=True
            canonical_first=False
            require_public_global=True
        """
        _ts = (og_first, canonical_first)
        if not any(_ts) or all(_ts):
            raise ValueError("submit one and only one of (og_first, canonical_first")

        url_fallback = None
        if require_public_global:
            url_fallback = self.get_fallback_url(require_public_netloc=True,
                                                 allow_localhosts=False,
                                                 )

        if og_first:
            ordering = ('og', 'canonical')
        elif canonical_first:
            ordering = ('canonical', 'og')

        for source in ordering:
            url = None
            if source == 'og':
                url = self.get_url_opengraph(require_public_global=require_public_global,
                                             url_fallback=url_fallback,
                                             )
            elif source == 'canonical':
                url = self.get_url_canonical(require_public_global=require_public_global,
                                             url_fallback=url_fallback,
                                             )
            if url:
                return url

        return self.absolute_url()

    # --------------------------------------------------------------------------

    def get_metadata_link(
        self,
        field,
        strategy=None,
        allow_encoded_uri=False,
        require_public_global=True,
    ):
        """sometimes links are bad; this tries to fix them.  most useful for meta images

        args:
            field

        kwargs:
            strategy=None
                ('all') or iterable ['og', 'dc', 'meta', 'page', 'twitter', ]
            allow_encoded_uri=False
            require_public_global=True

        if `require_public_global` is True, this will try to correct
            the data (relative to absolute) or reset to None.  This option will
            also require the fallback url to be on the public internet and not a
            localhost value.
        """
        # `_value` will be our raw value
        _value = self.get_metadata(field, strategy=strategy)
        if not _value:
            return None

        # `value` will be our clean value
        # remove whitespace, because some bad blogging platforms add in whitespace by printing elements on multiple lines. d'oh!
        # this also up data:image and normal links
        value = RE_whitespace.sub('', _value)

        # it's possible for an encoded URI to be an image
        # if that is the case, don't return it (this is `get_metadata_LINK`)
        if value[:11].lower().startswith('data:image/'):
            if allow_encoded_uri:
                return value
            return None

        # it is possible for a declared url to not have rfc valid characters
        # sometimes you'll find HTML documents in here. serious!
        is_valid_chars = RE_rfc3986_valid_characters.match(value)
        if not is_valid_chars:
            return None

        if require_public_global:
            _require_public_netloc = True
            _allow_localhosts = False
        else:
            _require_public_netloc = False
            _allow_localhosts = True

        # if the url is valid, RETURN IT
        if is_url_valid(
            value,
            require_public_netloc=_require_public_netloc,
            allow_localhosts=_allow_localhosts,
        ):
            return value

        # fallback url is used to drop to the domain
        url_fallback = self.get_fallback_url(require_public_netloc=_require_public_netloc,
                                             allow_localhosts=_allow_localhosts,
                                             )

        # try making it absolute
        value_fixed = url_to_absolute_url(value,
                                          url_fallback=url_fallback,
                                          require_public_netloc=_require_public_netloc,
                                          allow_localhosts=_allow_localhosts,
                                          )
        if is_url_valid(
            value_fixed,
            require_public_netloc=_require_public_netloc,
            allow_localhosts=_allow_localhosts,
        ):
            return value_fixed

        return None
