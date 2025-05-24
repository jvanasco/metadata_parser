import _socket  # noqa: I100,I201  # peername hack, see below

# stdlib
import cgi  # noqa: I100,I201
import collections
import datetime
from html import unescape as html_unescape
import logging
import os
import re
import socket  # peername hack, see below
import typing
from typing import Any
from typing import Callable
from typing import Dict
from typing import Iterable
from typing import List
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING
from typing import Union
import unicodedata
from urllib.parse import _ResultMixinStr  # what happens if you decode
from urllib.parse import ParseResult
from urllib.parse import ParseResultBytes
from urllib.parse import quote as url_quote
from urllib.parse import unquote as url_unquote
from urllib.parse import urlparse
from urllib.parse import urlunparse
import warnings

# pypi
from bs4 import BeautifulSoup
import requests
from requests.structures import CaseInsensitiveDict
from requests_toolbelt.utils.deprecated import get_encodings_from_content
from typing_extensions import Literal  # py38
from typing_extensions import Protocol  # py38

if TYPE_CHECKING:
    from bs4 import Tag as _bs4_Tag

if __debug__:
    # only used for testing. turn off in most production env with -o flags
    import pprint  # noqa: F401

FUTURE_BEHAVIOR = bool(int(os.getenv("METADATA_PARSER_FUTURE", "0")))

# ==============================================================================


__VERSION__ = "0.13.0"


# ------------------------------------------------------------------------------


log = logging.getLogger(__name__)


def warn_future(message: str) -> None:
    warnings.warn(message, FutureWarning, stacklevel=2)
    if FUTURE_BEHAVIOR:
        raise ValueError(message)


def warn_user(message: str) -> None:
    warnings.warn(message, UserWarning, stacklevel=2)


# ------------------------------------------------------------------------------

# defaults
DUMMY_URL = os.environ.get(
    "METADATA_PARSER__DUMMY_URL", "http://example.com/index.html"
)
ENCODING_FALLBACK = os.environ.get("METADATA_PARSER__ENCODING_FALLBACK", "ISO-8859-1")
TESTING = bool(int(os.environ.get("METADATA_PARSER__TESTING", "0")))

"""
# currently unused
MAX_CONNECTIONTIME = int(
    os.environ.get("METADATA_PARSER__MAX_CONNECTIONTIME", 20)
)  # in seconds
MAX_FILESIZE = int(
    os.environ.get("METADATA_PARSER__MAX_FILESIZE", 2 ** 19)
)  # bytes; this is .5MB
"""


TYPES_RESPONSE = Union["DummyResponse", requests.Response]
TYPES_PEERNAME = Tuple[str, int]  # (ip, port)
TYPE_URL_FETCH = Tuple[str, str, "ResponseHistory"]
TYPE_REQUESTS_TIMEOUT = Optional[
    Union[int, float, Tuple[int, int], Tuple[float, float]]
]

# ------------------------------------------------------------------------------

_DISABLE_TLDEXTRACT = bool(
    int(os.environ.get("METADATA_PARSER__DISABLE_TLDEXTRACT", "0"))
)
USE_TLDEXTRACT = None
if not _DISABLE_TLDEXTRACT:
    try:
        import tldextract

        USE_TLDEXTRACT = True
    except ImportError:
        log.info(
            "tldextract is not available on this system. "
            "medatadata_parser recommends installing tldextract"
        )
        USE_TLDEXTRACT = False

# ------------------------------------------------------------------------------


# peername hacks
# only use for these stdlib packages
# eventually will not be needed thanks to upstream changes in `requests`
try:
    _compatible_sockets: Tuple = (
        _socket.socket,
        socket._socketobject,  # type: ignore[attr-defined]
    )
except AttributeError:
    _compatible_sockets: Tuple = (_socket.socket,)  # type: ignore[no-redef]

# ------------------------------------------------------------------------------

# regex library

RE_ALL_NUMERIC = re.compile(r"^[\d\.]+$")
RE_bad_title = re.compile(
    r"""(?:<title>|&lt;title&gt;)(.*)(?:<?/title>|(?:&lt;)?/title&gt;)""", re.I
)
RE_canonical = re.compile("^canonical$", re.I)
RE_doctype = re.compile(r"^\s*<!DOCTYPE[^>]*>", re.IGNORECASE)
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
    re.VERBOSE | re.IGNORECASE,
)
RE_IPV4_ADDRESS = re.compile(
    r"^(\d{1,3})\.(\d{1,3}).(\d{1,3}).(\d{1,3})$"  # grab 4 octets
)
RE_PORT = re.compile(r"^" r"(?P<main>.+)" r":" r"(?P<port>\d+)" r"$", re.IGNORECASE)
RE_prefix_opengraph = re.compile(r"^og")
RE_prefix_rel_img_src = re.compile("^image_src$", re.I)
RE_prefix_twitter = re.compile(r"^twitter")

# we may need to test general validity of url components
RE_rfc3986_valid_characters = re.compile(
    r"""^[a-z0-9\-\.\_\~\:\/\?\#\[\]\@\!\$\&\'\(\)\*\+\,\;\=\%]+$""", re.I
)
r"""
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

RE_shortlink = re.compile("^shortlink$", re.I)
RE_whitespace = re.compile(r"\s+")

# based on DJANGO
# https://github.com/django/django/blob/master/django/core/validators.py
# not testing ipv6 right now, because rules are needed for ensuring they
# are correct
RE_VALID_NETLOC = re.compile(
    r"(?:"
    r"(?P<ipv4>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
    r"|"  # ...or ipv4
    #  r'(?P<ipv6>\[?[A-F0-9]*:[A-F0-9:]+\]?)'  # ...or ipv6
    #  r'|'
    r"(?P<localhost>localhost)"  # localhost...
    r"|"
    r"(?P<domain>([A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}(?<!-)\.?))"  # domain...
    r"(?P<port>:\d+)?"  # optional port
    r")",
    re.IGNORECASE,
)

# ------------------------------------------------------------------------------

# globals library

FIELDS_REQUIRE_HTTPS = (
    "og:image:secure_url",
    "og:audio:secure_url",
    "og:video:secure_url",
    # the following are just alternate representations of og: items
    "image:secure_url",
    "audio:secure_url",
    "video:secure_url",
)
PARSE_SAFE_FILES = (
    "html",
    "txt",
    "json",
    "htm",
    "xml",
    "php",
    "asp",
    "aspx",
    "ece",
    "xhtml",
    "cfm",
    "cgi",
)
# these aren't on the public internet
PRIVATE_HOSTNAMES = (
    "localhost",
    "127.0.0.1",
    "0.0.0.0",
)
SCHEMELESS_FIELDS_DISALLOW = (
    "canonical",
    "og:url",
)

"""
these fields can be upgraded to the current scheme if no scheme is detected
notes:
    `og:image:secure_url` is omitted, because it should be HTTPS
"""
SCHEMELESS_FIELDS_UPGRADEABLE = (
    "image",
    "og:image",
    "og:image:url",
    "og:audio",
    "og:video",
    "og:image:secure_url",
    "og:audio:secure_url",
    "og:video:secure_url",
)


# ------------------------------------------------------------------------------


def encode_ascii(text: str) -> str:
    """
    helper function to force ascii; some edge-cases have unicode line breaks in titles/etc.
    """
    if not text:
        text = ""
    _as_bytes = unicodedata.normalize("NFKD", text).encode("ascii", "ignore")
    _as_str = _as_bytes.decode("utf-8", "ignore")
    return _as_str


def decode_html(text: str) -> str:
    """
    helper function to decode text that has both HTML and non-ascii characters
    """
    text = encode_ascii(html_unescape(text))
    return text


# ------------------------------------------------------------------------------


def get_encoding_from_headers(headers: CaseInsensitiveDict) -> Optional[str]:
    """
    Returns encodings from given HTTP Header Dict.

    :param headers: dictionary to extract encoding from.
    :rtype: str

    `requests.get("http://example.com").headers` should be `requests.structures.CaseInsensitiveDict`

    ----------------------------------------------------------------------------

    Modified from `requests` version 2.x

    The Requests Library:

        Copyright 2017 Kenneth Reitz

        Licensed under the Apache License, Version 2.0 (the "License");
        you may not use this file except in compliance with the License.
        You may obtain a copy of the License at

            http://www.apache.org/licenses/LICENSE-2.0

        Unless required by applicable law or agreed to in writing, software
        distributed under the License is distributed on an "AS IS" BASIS,
        WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
        See the License for the specific language governing permissions and
        limitations under the License.
    """
    content_type = headers.get("content-type")
    if not content_type:
        return None
    content_type, params = cgi.parse_header(content_type)
    if "charset" in params:
        return params["charset"].strip("'\"")
    return None


# ------------------------------------------------------------------------------


def get_response_peername(resp: TYPES_RESPONSE) -> Optional[TYPES_PEERNAME]:
    """
    used to get the peername (ip+port) data from the request
    if a socket is found, caches this onto the request object

    IMPORTANT. this must happen BEFORE any content is consumed.

    `response` is really `requests.models.Response`

    This will UPGRADE the response object to have the following attribute:

        * _mp_peername
    """
    if not isinstance(resp, requests.Response) and not isinstance(resp, DummyResponse):
        # raise AllowableError("Not a HTTPResponse")
        log.debug("Not a supported HTTPResponse | %s", resp)
        log.debug("-> received a type of: %s", type(resp))
        return None

    if hasattr(resp, "_mp_peername"):
        return resp._mp_peername

    def _get_socket() -> Optional[socket.socket]:
        if isinstance(resp, DummyResponse):
            return None
        i = 0
        while True:
            i += 1
            try:
                if i == 1:
                    sock = resp.raw._connection.sock  # type: ignore[union-attr]
                elif i == 2:
                    sock = resp.raw._connection.sock.socket  # type: ignore[union-attr]
                elif i == 3:
                    sock = resp.raw._fp.fp._sock  # type: ignore[union-attr]
                elif i == 4:
                    sock = resp.raw._fp.fp._sock.socket  # type: ignore[union-attr]
                elif i == 5:
                    sock = resp.raw._fp.fp.raw._sock  # type: ignore[union-attr]
                else:
                    break
                if not isinstance(sock, _compatible_sockets):
                    raise AllowableError()
                return sock
            except Exception:
                pass
        return None

    sock = _get_socket()
    if sock:
        # only cache if we have a sock
        # we may want/need to call again
        resp._mp_peername = sock.getpeername()  # type: ignore [union-attr]
    else:
        resp._mp_peername = None  # type: ignore [union-attr]
    return resp._mp_peername  # type: ignore [union-attr]


# ------------------------------------------------------------------------------


def response_peername__hook(resp: TYPES_RESPONSE, *args, **kwargs) -> None:
    get_response_peername(resp)
    # do not return anything


def safe_sample(source: Union[str, bytes]) -> bytes:
    if isinstance(source, bytes):
        _sample = source[:1024]
    else:
        # this block can cause an error on PY3 depending on where the data came
        # from such as what the source is (from a request vs a document/test)
        # thanks, @keyz182 for the PR/investigation https://github.com/jvanasco/metadata_parser/pull/16
        _sample = (source.encode())[:1024]
    return _sample


def derive_encoding__hook(resp: TYPES_RESPONSE, *args, **kwargs) -> None:
    """
    a note about `requests`

    `response.content` is the raw response bytes
    `response.text` is `response.content` decoded to the identified codec or
                    the fallback codec.

    This fallback codec is normally iso-8859-1 (latin-1) which is defined by the
    RFC for HTTP as the default when no codec is provided in the headers or
    body. This hook exists because users in certain regions may expect the
    servers to not follow RFC and for the default encoding to be different.
    """
    if TYPE_CHECKING:
        assert hasattr(resp, "_encoding_fallback")
        assert hasattr(resp, "_encoding_content")
        assert hasattr(resp, "_encoding_headers")

    resp._encoding_fallback = ENCODING_FALLBACK
    # modified version, returns `None` if no charset available
    resp._encoding_headers = get_encoding_from_headers(resp.headers)
    resp._encoding_content = None
    if not resp._encoding_headers and resp.content:
        # html5 spec requires a meta-charset in the first 1024 bytes
        _sample = safe_sample(resp.content)
        resp._encoding_content = get_encodings_from_content(_sample)
    if resp._encoding_content:
        # it's a list
        resp.encoding = resp._encoding_content[0]
    else:
        resp.encoding = resp._encoding_headers or resp._encoding_fallback
    # do not return anything


# ------------------------------------------------------------------------------


def is_hostname_valid(
    hostname: str,
    allow_localhosts: bool = True,
    require_public_netloc: bool = False,
) -> bool:
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
    parsed: Union[ParseResult, ParseResultBytes, _ResultMixinStr],
    require_public_netloc: Optional[bool] = True,
    allow_localhosts: Optional[bool] = True,
    http_only: Optional[bool] = True,
) -> bool:
    """returns bool
    `http_only`
        defaults True
        requires http or https for the scheme
    """
    if isinstance(parsed, ParseResultBytes):
        parsed = parsed.decode()
    assert isinstance(parsed, ParseResult)
    if __debug__:
        log.debug("is_parsed_valid_url = %s", parsed)
    if not all((parsed.scheme, parsed.netloc)):
        if __debug__:
            log.debug(" FALSE - missing `scheme` or `netloc`")
        return False
    if http_only:
        if parsed.scheme not in ("http", "https"):
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
        try:
            # some py3 versions will have a ValueError here, e.g.
            #   ValueError: invalid literal for int() with base 10: '8080:8080'
            _port = parsed.port
        except ValueError:
            log.debug(" could not access parsed.port")
            return False

        # this can be a fast check..
        # note this is done AFTER we clean up a potential port grouping
        if _hostname:
            if __debug__:
                log.debug(" validating against PRIVATE_HOSTNAMES")
            if _hostname.lower() in PRIVATE_HOSTNAMES:
                if __debug__:
                    log.debug(" matched PRIVATE_HOSTNAMES")
                if allow_localhosts:
                    return True
                return False

        _netloc_groudict = _netloc_match.groupdict()
        if _netloc_groudict["ipv4"] is not None:
            if _hostname:
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
            if _hostname:
                if _hostname == "localhost":
                    if __debug__:
                        log.debug(" localhost!")
                    return False
                if RE_ALL_NUMERIC.match(_hostname):
                    if __debug__:
                        log.debug(
                            " This only has numeric characters. "
                            "this is probably a fake or typo ip address."
                        )
                    return False
            if _port:
                try:
                    _port = int(_port)
                    if parsed.port != _port:
                        if __debug__:
                            log.debug(" netloc.port does not match our regex _port")
                        return False
                except ValueError:
                    if __debug__:
                        log.debug(" _port is not an int")
                    return False
            if _hostname:
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


def is_parsed_valid_relative(parsed: ParseResult) -> bool:
    """returns bool"""
    assert isinstance(parsed, ParseResult)
    if parsed.path and not any((parsed.scheme, parsed.hostname)):
        return True
    return False


def parsed_to_relative(
    parsed: ParseResult,
    parsed_fallback: Optional[ParseResult] = None,
) -> str:
    """turns a parsed url into a full relative path"""
    assert isinstance(parsed, ParseResult)
    _path = parsed.path
    # cleanup, might be unnecessary now
    if _path and _path[0] != "/":
        if parsed_fallback:
            assert isinstance(parsed_fallback, ParseResult)
            _path_fallback = parsed_fallback.path
            if _path_fallback and _path_fallback[0] != "/":
                # there's not much we can do here... pretend there's no fallback
                _path = "/%s" % _path
            else:
                _path_fallback_dir = "/".join(_path_fallback.split("/")[:-1])
                _path = "%s/%s" % (_path_fallback_dir, _path)
        else:
            # prepend a slash
            _path = "/%s" % _path
    if parsed.query:
        _path += "?" + parsed.query
    if parsed.fragment:
        _path += "#" + parsed.fragment
    return _path


def fix_unicode_url(
    url: str,
    encoding: Optional[str] = None,
    urlparser: Callable[[str], ParseResult] = urlparse,
) -> str:
    """
    some cms systems will put unicode in their canonical url
    this is not allowed by rfc.
    currently this function will update the PATH but not the kwargs.
    perhaps it should.
    rfc3986 says that characters should be put into utf8 then percent encoded

    kwargs:
        `encoding` - used for python2 encoding
        `urlparser` - defaults to standard `urlparse`, can be substituted with
                      a cacheable version.
    """
    parsed = urlparser(url)
    if parsed.path in ("", "/"):
        # can't do anything
        return url
    if RE_rfc3986_valid_characters.match(parsed.path):
        # again, can't do anything
        return url
    # okay, we know we have bad items in the path, so try and upgrade!
    # turn the namedtuple from urlparse into something we can edit
    candidate = [i for i in parsed]
    for _idx in [2]:  # 2=path, 3=params, 4=queryparams, 5fragment
        try:
            candidate[_idx] = parsed[_idx]
            candidate[_idx] = url_quote(url_unquote(candidate[_idx]))
        except Exception as exc:
            log.debug("fix_unicode_url failure: %s | %s | %s", url, encoding, exc)
            return url
    _url = urlunparse(candidate)
    return _url


def is_url_valid(
    url: str,
    require_public_netloc: Optional[bool] = None,
    allow_localhosts: Optional[bool] = None,
    urlparser: Callable[[str], ParseResult] = urlparse,
) -> Union[Literal[False], ParseResult]:
    """
    tries to parse a url. if valid returns `ParseResult`
    (boolean eval is True); if invalid returns `False`
    kwargs:
        `require_public_netloc` -
        `allow_localhosts` -
        `urlparser` - defaults to standard `urlparse`, can be substituted with
                      a cacheable version.
    """
    if url is None:
        return False
    parsed = urlparser(url)
    if is_parsed_valid_url(
        parsed,
        require_public_netloc=require_public_netloc,
        allow_localhosts=allow_localhosts,
    ):
        return parsed
    return False


def url_to_absolute_url(
    url_test: Optional[str],
    url_fallback: Optional[str] = None,
    require_public_netloc: Optional[bool] = None,
    allow_localhosts: Optional[bool] = None,
    urlparser: Callable[[str], ParseResult] = urlparse,
) -> Optional[str]:
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
        `urlparser` - defaults to standard `urlparse`, can be substituted with
                      a cacheable version.
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

    if TYPE_CHECKING:
        assert url_test is not None

    parsed = urlparser(url_test)

    # if we passed in a url, we can't remount it onto another domain
    if parsed.hostname:
        if not is_hostname_valid(parsed.hostname, allow_localhosts=True):
            return None

    _path = parsed.path
    if _path:
        # sanity check
        # some stock plugins create invalid urls/files like '/...' in meta-data
        known_invalid_plugins_paths = ["/..."]
        if _path[0] != "/":
            # prepend a slash
            _path = "/%s" % _path
        if _path in known_invalid_plugins_paths:
            return url_fallback

    parsed_fallback = urlparser(url_fallback) if url_fallback else None

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
            if TYPE_CHECKING:
                assert parsed_fallback is not None
            if (parsed_fallback.scheme == parsed.scheme) or (
                parsed_fallback.netloc == parsed.netloc
            ):
                return url_fallback

    # initialize our return value
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
            if TYPE_CHECKING:
                assert parsed_fallback is not None
            if is_parsed_valid_url(
                parsed_fallback,
                require_public_netloc=require_public_netloc,
                allow_localhosts=allow_localhosts,
            ):
                parsed_domain_source = parsed_fallback

    if parsed_domain_source:
        rval = "%s://%s%s" % (
            parsed_domain_source.scheme,
            parsed_domain_source.netloc,
            _path,
        )
    return rval


# ------------------------------------------------------------------------------


class InvalidDocument(Exception):
    message: str

    def __init__(self, message: str = ""):
        self.message = message

    def __str__(self) -> str:
        return "InvalidDocument: %s" % (self.message)


class NotParsable(Exception):
    raised: Optional[requests.exceptions.RequestException]
    code: Optional[int]
    metadataParser: Optional["MetadataParser"]
    response: Optional[TYPES_RESPONSE]

    def __init__(
        self,
        message: str = "",
        raised: Optional[requests.exceptions.RequestException] = None,
        code: Optional[int] = None,
        metadataParser: Optional["MetadataParser"] = None,
        response: Optional[TYPES_RESPONSE] = None,
    ):
        self.message = message
        self.raised = raised
        self.code = code
        self.metadataParser = metadataParser
        self.response = response

    def __str__(self) -> str:
        return "NotParsable: %s | %s | %s" % (self.message, self.code, self.raised)


class NotParsableJson(NotParsable):
    def __str__(self) -> str:
        return "NotParsableJson: %s | %s | %s" % (self.message, self.code, self.raised)


class NotParsableRedirect(NotParsable):
    """Raised if a redirect is detected, but there is no Location header."""

    def __str__(self) -> str:
        return "NotParsableRedirect: %s | %s | %s" % (
            self.message,
            self.code,
            self.raised,
        )


class NotParsableFetchError(NotParsable):
    def __str__(self) -> str:
        return "NotParsableFetchError: %s | %s | %s" % (
            self.message,
            self.code,
            self.raised,
        )


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

    location: str
    code: Optional[int]
    response: Optional[TYPES_RESPONSE]
    metadataParser: Optional["MetadataParser"]

    def __init__(
        self,
        location: str = "",
        code: Optional[int] = None,
        response: Optional[TYPES_RESPONSE] = None,
        metadataParser: Optional["MetadataParser"] = None,
    ):
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

    text: str
    url: str
    status_code: int
    encoding: str
    elapsed_seconds: float = 0
    history: List
    headers: CaseInsensitiveDict
    content: Optional[Union[str, bytes]] = None
    default_encoding: str

    def __init__(
        self,
        text: str = "",
        url: str = "",
        status_code: int = 200,
        encoding: Optional[str] = None,
        elapsed_seconds: float = 0,
        headers: Optional[CaseInsensitiveDict] = None,
        content: Optional[typing.AnyStr] = None,
        derive_encoding: Optional[bool] = None,
        default_encoding: Optional[str] = None,
    ):
        self.text = text
        self.url = url
        self.status_code = status_code
        self.elapsed = datetime.timedelta(0, elapsed_seconds)
        self.headers = headers if headers is not None else CaseInsensitiveDict()
        self.history = []
        self.content = content

        # start `encoding` block
        if encoding:
            self.encoding = encoding
        elif derive_encoding:
            # only examine first 1024 bytes. in this case chars. utf could be 4x chars
            _sample = safe_sample(text)
            encodings = get_encodings_from_content(_sample)
            if encodings:
                self.encoding = encoding = encodings[0]
        self.default_encoding = default_encoding or ENCODING_FALLBACK
        # second phase cleanup
        if not encoding:
            self.encoding = self.default_encoding
        # end `encoding` block


# ------------------------------------------------------------------------------


class ResponseHistory(object):
    history: Optional[Iterable] = None

    def __init__(self, resp: TYPES_RESPONSE):
        """
        :param resp: A :class:`requests.Response` object to compute history of
        :type resp: class:`requests.Response`
        """
        _history = []
        if resp.history:
            for _rh in resp.history:
                _history.append((_rh.status_code, _rh.url))
        _history.append((resp.status_code, resp.url))
        self.history = _history

    def log(
        self,
        prefix: str = "ResponseHistory",
        logger: Callable[..., None] = log.error,
    ) -> None:
        """
        :param prefix: Prefix for logging, defaults to "ResponseHistory"
        :type prefix: str
        :param logger: default `log.error`
        :type logger: logging stream
        """
        if self.history:
            for _idx, _history in enumerate(self.history):
                logger(
                    "%s | %s | %s : %s ",
                    prefix,
                    _idx,
                    _history[0],  # status_code
                    _history[1],  # url
                )


class _UrlParserCacheable(Protocol):
    urlparse: Callable[[str], ParseResult]


class UrlParserCacheable(_UrlParserCacheable):
    """
    class for caching calls to urlparse

    this simply manipulates a dict
    """

    cache: collections.OrderedDict
    maxitems: int
    urlparser: Callable[[str], ParseResult]

    def __init__(
        self,
        maxitems: int = 30,
        urlparser: Callable[[str], ParseResult] = urlparse,
    ):
        """
        :param maxitems: maximum items to cache, default 30
        :type maxitems: int, optional
        """
        self.cache = collections.OrderedDict()
        self.maxitems = maxitems
        self.urlparser = urlparser

    def urlparse(self, url: str) -> ParseResult:
        """
        :param url: url to parse
        :type url: str
        """
        if url not in self.cache:
            self.cache[url] = self.urlparser(url)
            if len(self.cache) > self.maxitems:
                self.cache.popitem(last=False)
        return self.cache[url]


class ParsedResult(object):
    """
    Class for managing a dict of metadata
    The dict can contain string or array values for legacy compatability reasons.

    Version Tracking:
    * Version tracking was introduced in 0.9.19 via the `_v` metadata entry.
      In the future, payloads without the `_v` will be interpreted as being
      in the pre-versioning format (which is the same as v1)

    Any changes to the versioning should be tracked in this docstring, as the
    readme/docs are not necessarily installed locally.
    """

    metadata: Dict
    soup: Optional[BeautifulSoup] = None
    response_history: Optional[ResponseHistory] = (
        None  # only stashing `ResponseHistory` if we have it
    )
    _version: int = 1  # version tracking
    default_encoder: Optional[Callable[[str], str]] = None
    og_minimum_requirements: List = ["title", "type", "image", "url"]
    twitter_sections: List = ["card", "title", "site", "description"]
    strategy: Union[List[str], str] = ["og", "dc", "meta", "page", "twitter"]

    _get_metadata__last_strategy: Optional[str] = None

    def __init__(self):
        self.metadata = {
            "og": {},
            "meta": {},
            "dc": {},
            "page": {},
            "twitter": {},
            "_internal": {},
            "_v": ParsedResult._version,  # version tracking
        }

    @property
    def metadata_version(self) -> Optional[int]:
        return self.metadata.get("_v", None)

    @property
    def metadata_encoding(self) -> Optional[str]:
        return self.metadata.get("_internal", {}).get("encoding", None)

    def _add_discovered(
        self,
        _target_container_key: str,
        _target_key: str,
        _raw_value: str,
        _formatted_value: Optional[Union[str, Dict]] = None,
    ):
        """
        unified function to add data.
        because this information is often stored in a database, to conserve
        space it will eat some CPU functions and store the data as an list
        or string.
        """
        if _formatted_value is None:
            _formatted_value = _raw_value.strip()
        _target_container = self.metadata[_target_container_key]
        if _target_key not in _target_container:
            _target_container[_target_key] = _formatted_value
        else:
            _current_value = _target_container[_target_key]
            if not isinstance(_current_value, list):
                if _formatted_value == _current_value:
                    return
                _target_container[_target_key] = [
                    _target_container[_target_key],
                    _formatted_value,
                ]
            else:
                if _formatted_value not in _target_container[_target_key]:
                    _target_container[_target_key].append(_formatted_value)

    def _coerce_validate_strategy(
        self,
        strategy: Union[List[str], str, None] = None,
    ) -> Union[List, str]:
        """normalize a strategy into a valid option"""
        if strategy:
            if isinstance(strategy, str):
                if strategy != "all":
                    raise ValueError("If `strategy` is not a `list`, it must be 'all'.")
            elif isinstance(strategy, list):
                _invalids = []
                for _candidate in strategy:
                    if _candidate not in self.strategy:
                        _invalids.append(_candidate)
                if "all" in strategy:
                    raise ValueError('Submit "all" as a `str`, not in a `list`.')
                if _invalids:
                    raise ValueError("invalid strategy: %s" % _invalids)
        else:
            # use our default list
            strategy = self.strategy
        return strategy

    def get_metadata(
        self,
        field: str,
        strategy: Union[list, str, None] = None,
        encoder: Optional[Callable[[str], str]] = None,
    ) -> Union[str, Dict[str, Union[str, Dict]], None]:
        """
        LEGACY. DEPRECATED.  DO NOT USE THIS.

        `get_metadata`
        looks for the field in various stores.  defaults to the core
        strategy, though you may specify a certain item.  if you search for
        'all' it will return a dict of all values.

        This is a legacy method and is being deprecated in favor of `get_metadatas`
        This method will always return a string for the field value, however it
        is possible the field contains multiple elements or even a dict if the
        source was dublincore.

        In comparison, `get_metadatas` will always return a list for the values.

        In the case of DC/DublinCore metadata, this will return the first 'simple'
        pairing (key/value - without a scheme/language) or the first element if no
        simple match exists.

        This function will return different types depending on the input:

        if `strategy` is a single type:
            `str` or `None`

        if `strategy` is a list:
            `str` or `None`, with `str` being the first match
            self._get_metadata__last_strategy will persist the matching strategy

        if `strategy` is "all":
            `dict` of {strategy: result}

        :param field:
          The field to retrieve
        :type field: str

        :param strategy:
          Where to search for the metadata. such as 'all' or
          iterable like ['og', 'dc', 'meta', 'page', 'twitter', ]
        :type strategy: string or list

        :param encoder:
          a function, such as `encode_ascii`, to encode values before returning.
          a valid `encoder` accepts one(1) arg.
          if a `default_encoder` is registered, the string "raw" will disable it.
        :type encoder:
          function or "raw"
        """
        warn_future(
            """`ParsedResult.get_metadata` returns a string and is deprecated """
            """in favor of `get_metadatas` which returns a list. """
            """This will be removed in the next minor or major release."""
        )
        strategy = self._coerce_validate_strategy(strategy)
        self._get_metadata__last_strategy = None

        if encoder is None:
            encoder = self.default_encoder
        elif encoder == "raw":
            encoder = None

        def _lookup(store: str) -> Optional[Union[str, Dict]]:
            if field in self.metadata[store]:
                val = self.metadata[store][field]
                if store == "dc":
                    # dublincore will be different. it uses dicts by default
                    # this is a one-element match
                    if isinstance(val, dict):
                        val = val["content"]
                    else:
                        _opt = None
                        for _val in val:
                            if len(_val.keys()) == 1:
                                _opt = _val["content"]
                                break
                        if _opt is None:
                            _opt = val[0]["content"]
                        val = _opt
                else:
                    if isinstance(val, list):
                        val = val[0]
                if encoder:
                    val = encoder(val)
                return val
            return None

        # `_coerce_validate_strategy` ensured a compliant strategy
        if isinstance(strategy, list):
            for store in strategy:
                if store in self.metadata:
                    val = _lookup(store)
                    if val is not None:
                        self._get_metadata__last_strategy = store
                        return val
            return None
        elif strategy == "all":
            rval: Dict = {}
            for store in self.metadata:
                if store == "_v":
                    continue
                if field in self.metadata[store]:
                    val = _lookup(store)
                    rval[store] = val
            return rval
        else:
            raise ValueError("unsupported strategy")

    def get_metadatas(
        self,
        field: str,
        strategy: Union[List[str], str, None] = None,
        encoder: Optional[Callable[[str], str]] = None,
    ) -> Optional[Union[Dict, List]]:
        """
        looks for the field in various stores.  defaults to the core
        strategy, though you may specify a certain item.  if you search for
        'all' it will return a dict of all values.

        This method replaced the legacy method `get_metadatas`.
        This method will always return a list.

        :param field:
          The field to retrieve
        :type field: str

        :param strategy:
          Where to search for the metadata. such as 'all' or
          iterable like ['og', 'dc', 'meta', 'page', 'twitter', ]
        :type strategy: string or list

        :param encoder:
          a function, such as `encode_ascii`, to encode values before returning.
          a valid `encoder` accepts one(1) arg.
          if a `default_encoder` is registered, the string "raw" will disable it.
        :type encoder:
          function or "raw"
        """
        strategy = self._coerce_validate_strategy(strategy)

        if encoder is None:
            encoder = self.default_encoder
        elif encoder == "raw":
            encoder = None

        def _lookup(store: str) -> Optional[List]:
            if field in self.metadata[store]:
                val = self.metadata[store][field]
                if not isinstance(val, list):
                    val = [
                        val,
                    ]
                if encoder:
                    val = [encoder(v) for v in val]
                return val
            return None

        # `_coerce_validate_strategy` ensured a compliant strategy
        if isinstance(strategy, list):
            # returns List or None
            for store in strategy:
                if store in self.metadata:
                    val = _lookup(store)
                    if val is not None:
                        return val
            return None
        elif strategy == "all":
            # returns Dict or None
            rval: Dict = {}
            for store in self.metadata:
                if store == "_v":
                    continue
                if field in self.metadata[store]:
                    val = _lookup(store)
                    rval[store] = val
            return rval
        else:
            raise ValueError("unsupported strategy")

    def is_opengraph_minimum(self) -> bool:
        """
        returns true/false if the page has the minimum amount of opengraph tags
        """
        return all(
            [
                self.metadata["og"].get(attr, None)
                for attr in self.og_minimum_requirements
            ]
        )


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

    url: Optional[str] = None
    url_actual: Optional[str] = None
    strategy: Union[List[str], str, None] = None
    LEN_MAX_TITLE: int = 255
    only_parse_file_extensions: Optional[List[str]] = None
    allow_localhosts: Optional[bool] = None
    require_public_netloc: Optional[bool] = None
    force_doctype: Optional[bool] = None
    requests_timeout: TYPE_REQUESTS_TIMEOUT = None
    peername: Optional[TYPES_PEERNAME] = None
    is_redirect: Optional[bool] = None
    is_redirect_unique: Optional[bool] = None
    is_redirect_same_host: Optional[bool] = None

    force_parse: Optional[bool] = None
    force_parse_invalid_content_type: Optional[bool] = None
    only_parse_http_ok: Optional[bool] = None
    requests_session: Optional[requests.Session] = None
    derive_encoding: Optional[bool] = None
    default_encoding: Optional[str] = None
    default_encoder: Optional[Callable[[str], str]] = None
    support_malformed: Optional[bool] = None

    urlparse: Callable[[str], ParseResult]
    _cached_urlparser: Optional[_UrlParserCacheable]

    # this has a per-parser default tuple
    # it can be upgraded manually
    schemeless_fields_upgradeable: Tuple[str, ...] = SCHEMELESS_FIELDS_UPGRADEABLE
    schemeless_fields_disallow: Tuple[str, ...] = SCHEMELESS_FIELDS_DISALLOW

    _content_types_parse: Tuple[str, ...] = ("text/html",)
    _content_types_noparse: Tuple[str, ...] = ("application/json",)

    response: Optional[TYPES_RESPONSE]

    def __init__(
        self,
        url: Optional[str] = None,
        html: Optional[str] = None,
        strategy: Union[List[str], str, None] = None,
        url_data: Optional[Dict[str, Any]] = None,
        url_headers: Optional[Dict[str, str]] = None,
        force_parse: bool = False,
        ssl_verify: bool = True,
        only_parse_file_extensions: Optional[List[str]] = None,
        force_parse_invalid_content_type: bool = False,
        require_public_netloc: bool = True,
        allow_localhosts: Optional[bool] = None,
        force_doctype: bool = False,
        requests_timeout: TYPE_REQUESTS_TIMEOUT = None,
        raise_on_invalid: bool = False,
        search_head_only: bool = False,
        allow_redirects: bool = True,
        requests_session: Optional[requests.Session] = None,
        only_parse_http_ok: bool = True,
        defer_fetch: bool = False,
        derive_encoding: bool = True,
        html_encoding: Optional[str] = None,
        default_encoding: Optional[str] = None,
        default_encoder: Optional[Callable[[str], str]] = None,
        retry_dropped_without_headers: Optional[bool] = None,
        support_malformed: Optional[bool] = None,
        cached_urlparser: Union[bool, int, Callable[[str], ParseResult]] = True,
        cached_urlparser_maxitems: Optional[int] = None,
    ):
        """
        creates a new `MetadataParser` instance.

        kwargs:
            `url`
                url to parse
            `html`
                instead of a url, parse raw html
            `html_encoding`
                if html is passed, optionally note the encoding
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
                why? some cms give a bad doctype (like nasa.gov) which can break
                lxml/bs4. some cms also give a non-html doctype, which will remove
                the elements from 'head' when parsed.
            `requests_timeout`
                default: None
                if set, proxies the value into `requests.get` as `timeout`
            `raise_on_invalid`
                default: False
                if True, will raise an InvalidDocument exception if the response
                does not look like a proper html document
            `search_head_only`
                default: False
                if `True`, will only search the document head for meta information.
                `search_head_only=True` is the legacy behavior, but missed too many
                bad html implementations.
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
            `derive_encoding`:
                default: True
                if True, will try to pull encoding from the content
            `default_encoder`:
                default: None
                Register a default encoder with the parsed result
            `default_encoding`
                default: None
                per-parser default
            `retry_dropped_without_headers`
                default: None
                if True, will retry a dropped connection without headers
            `support_malformed`
                default: None
                if True, will support parsing some commonly malformed tag implementations
            `cached_urlparser`
                default: True
                options: True: use a instance of UrlParserCacheable(maxitems=30)
                       : INT: use a instance of UrlParserCacheable(maxitems=cached_urlparser)
                            DEPRECATED in v13.0
                            instead, set `cached_urlparser=True, cached_urlparser_maxitems=maxitems
                       : None/False - use native urlparse
                       : callable - use as a custom urlparse
            `cached_urlparser_maxitems`
                default: None
                options: int: sets maxitems
        """
        if __debug__:
            log.debug("MetadataParser.__init__(%s)", url)
        if url is not None:
            url = url.strip()
        self.parsed_result = ParsedResult()
        if cached_urlparser_maxitems:
            if cached_urlparser is not True:
                raise ValueError(
                    "`cached_urlparser_maxitems` requires `cached_urlparser=True`"
                )
        if cached_urlparser == 0:
            warn_future(
                "Supplying `0` to `cached_urlparser` to set maxitems is deprecated. "
                "This will be removed in the next major or minor release."
                "Supply `cached_urlparser=False` instead."
            )
            cached_urlparser = False
        if cached_urlparser:
            if isinstance(cached_urlparser, int):
                # build a default parser with maxitems
                warn_future(
                    "Supplying an int to `cached_urlparser` to set maxitems is deprecated. "
                    "This will be removed in the next major or minor release."
                    "Supply `cached_urlparser=True, cached_urlparser_maxitems=int` instead."
                )
                # coerce args for the next block
                cached_urlparser_maxitems = cached_urlparser
                cached_urlparser = True
            if cached_urlparser is True:
                # build a default parser
                if cached_urlparser_maxitems is not None:
                    _cached_urlparser = UrlParserCacheable(
                        maxitems=cached_urlparser_maxitems
                    )
                else:
                    _cached_urlparser = UrlParserCacheable()
                self._cached_urlparser = _cached_urlparser  # stash it
                self.urlparse = _cached_urlparser.urlparse
            else:
                if not callable(cached_urlparser):
                    raise ValueError("`cached_urlparser` must be a callable")
                self._cached_urlparser = None
                self.urlparse = cached_urlparser
        else:
            self.urlparse = urlparse
        if strategy:
            self.parsed_result.strategy = strategy
        self.url = self.parsed_result.metadata["_internal"]["url"] = url
        self.url_actual = self.parsed_result.metadata["_internal"]["url_actual"] = url
        self.ssl_verify = ssl_verify
        self.force_doctype = force_doctype
        self.response = None
        self.response_headers: Dict = {}
        self.require_public_netloc = require_public_netloc
        self.allow_localhosts = allow_localhosts
        self.requests_timeout = requests_timeout
        self.allow_redirects = allow_redirects
        self.force_parse = force_parse
        self.force_parse_invalid_content_type = force_parse_invalid_content_type
        self.only_parse_http_ok = only_parse_http_ok
        self.search_head_only = search_head_only
        self.raise_on_invalid = raise_on_invalid
        self.requests_session = requests_session
        self.derive_encoding = derive_encoding
        self.default_encoding = default_encoding
        self.support_malformed = support_malformed
        if only_parse_file_extensions is not None:
            self.only_parse_file_extensions = only_parse_file_extensions
        if default_encoder is not None:
            self.default_encoder = default_encoder
            self.parsed_result.default_encoder = default_encoder
        _response_history = None  # scoping, should this be supported as a pass-in?
        if html is not None:
            # mock a response
            # if `html_encoding` was provided as a kwarg, it becomes the encoding
            self.response = DummyResponse(
                text=html,
                url=(url or DUMMY_URL),
                encoding=html_encoding,
                derive_encoding=derive_encoding,
                default_encoding=default_encoding,
            )
        else:
            if html_encoding is not None:
                warn_user(
                    """`html_encoding` should only be provided when """
                    """`html` is `None`"""
                )
            # we may not have a url for tests or other api usage
            # note that `html_encoding` is pulled out here.
            if url:
                if defer_fetch:

                    def deferred_fetch() -> None:
                        (html, html_encoding, _response_history) = self.fetch_url(
                            url_data=url_data,
                            url_headers=url_headers,
                            retry_dropped_without_headers=retry_dropped_without_headers,
                        )
                        self.parse(
                            html,
                            html_encoding=html_encoding,
                            support_malformed=support_malformed,
                            response_history=_response_history,
                        )
                        return

                    self.deferred_fetch = deferred_fetch  # type: ignore[method-assign]
                    return
                (html, html_encoding, _response_history) = self.fetch_url(
                    url_data=url_data,
                    url_headers=url_headers,
                    retry_dropped_without_headers=retry_dropped_without_headers,
                )
            else:
                # our html should always be unicode coming from `requests`
                html = ""

        if html:
            self.parse(
                html,
                html_encoding=html_encoding,
                support_malformed=support_malformed,
                response_history=_response_history,
            )

    # --------------------------------------------------------------------------

    @property
    def metadata(self):
        # deprecating in 1.0
        warn_future(
            "MetadataParser.metadata is deprecated in 1.0; Operate on the parsed result directly."
        )
        return self.parsed_result.metadata

    @property
    def metadata_version(self):
        # deprecating in 1.0
        warn_future(
            "MetadataParser.metadata_version is deprecated in 1.0; Operate on the parsed result directly."
        )
        return self.parsed_result.metadata_version

    @property
    def metadata_encoding(self):
        # deprecating in 1.0
        warn_future(
            "MetadataParser.metadata_encoding is deprecated in 1.0; Operate on the parsed result directly."
        )
        return self.parsed_result.metadata_encoding

    @property
    def soup(self):
        # deprecating in 1.0
        warn_future(
            "MetadataParser.soup is deprecated in 1.0; Operate on the parsed result directly."
        )
        return self.parsed_result.soup

    def get_metadata(
        self,
        field: str,
        strategy: Union[list, str, None] = None,
        encoder: Optional[Callable[[str], str]] = None,
    ) -> Union[str, Dict[str, Union[str, Dict]], None]:
        # deprecating in 1.0; operate on the result instead
        warn_future(
            "MetadataParser.get_metadata is deprecated in 1.0; Operate on the parsed result directly."
        )
        return self.parsed_result.get_metadata(
            field, strategy=strategy, encoder=encoder
        )

    def get_metadatas(
        self,
        field,
        strategy: Union[List[str], str, None] = None,
        encoder: Optional[Callable[[str], str]] = None,
    ) -> Optional[Union[Dict, List]]:
        # deprecating in 1.0; operate on the result instead
        warn_future(
            "MetadataParser.get_metadatas is deprecated in 1.0; Operate on the parsed result directly."
        )
        return self.parsed_result.get_metadatas(
            field, strategy=strategy, encoder=encoder
        )

    def is_opengraph_minimum(self) -> bool:
        # deprecating in 1.0
        warn_future(
            "MetadataParser.is_opengraph_minimum is deprecated in 1.0; Operate on the parsed result directly."
        )
        return self.parsed_result.is_opengraph_minimum()

    # --------------------------------------------------------------------------

    def deferred_fetch(self):
        # allows for a deferrable fetch; override in __init__
        raise ValueError("no `deferred_fetch` set")

    # --------------------------------------------------------------------------

    def _response_encoding(self) -> Optional[str]:
        if self.response:
            return self.response.encoding
        return self.default_encoding or ENCODING_FALLBACK

    def fetch_url(
        self,
        url_data: Optional[Dict[str, Any]] = None,  # ???: required
        url_headers: Optional[Union[CaseInsensitiveDict, Dict[str, Any]]] = None,
        force_parse: Optional[bool] = None,  # `None` will use `self.force_parse`
        force_parse_invalid_content_type: Optional[bool] = None,
        allow_redirects: Optional[bool] = None,
        ssl_verify: Optional[bool] = None,
        requests_timeout: TYPE_REQUESTS_TIMEOUT = None,
        requests_session: Optional[requests.Session] = None,
        only_parse_http_ok: Optional[bool] = None,
        derive_encoding: Optional[bool] = None,
        default_encoding: Optional[str] = None,
        retry_dropped_without_headers: Optional[bool] = None,
    ) -> TYPE_URL_FETCH:
        """
        fetches the url and returns a tuple of (html, html_encoding).
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
            derive_encoding=None
                defaults to self.derive_encoding if None
            default_encoding=None
                defaults to self.default_encoding if None
            retry_dropped_without_headers=None
                if true, will retry_dropped_without_headers
        """
        if __debug__:
            log.error("MetadataParser.fetch_url(%s)", self.url)
        # should we even download/parse this?
        force_parse = force_parse if force_parse is not None else self.force_parse
        force_parse_invalid_content_type = (
            force_parse_invalid_content_type
            if force_parse_invalid_content_type is not None
            else self.force_parse_invalid_content_type
        )
        only_parse_http_ok = (
            only_parse_http_ok
            if only_parse_http_ok is not None
            else self.only_parse_http_ok
        )
        if not force_parse and self.only_parse_file_extensions is not None:
            assert self.url
            parsed = self.urlparse(self.url)
            path = parsed.path
            if path:
                url_fpath = path.split(".")
                if len(url_fpath) == 0:
                    # i have no idea what this file is, it's likely using a
                    # directory index
                    pass
                elif len(url_fpath) > 1:
                    url_fext = url_fpath[-1]
                    if url_fext in self.only_parse_file_extensions:
                        pass
                    else:
                        log.error(
                            "NotParsable | %s | unknown filetype, request: ",
                            self.url,
                        )
                        raise NotParsable(
                            "I don't know what this file is",
                            metadataParser=self,
                        )

        # borrowing some ideas from
        # http://code.google.com/p/feedparser/source/browse/trunk/feedparser/feedparser.py#3701
        if not url_headers:
            url_headers = {}

        # if someone does usertracking with sharethis.com, they get a hashbang
        # like this: http://example.com/page#.UHeGb2nuVo8
        # that fucks things up.
        assert self.url
        url = self.url.split("#")[0]

        # scoping for return values
        html = html_encoding = response_history = None
        try:
            # requests gives us unicode and the correct encoding, yay
            allow_redirects = (
                allow_redirects if allow_redirects is not None else self.allow_redirects
            )
            requests_timeout = (
                requests_timeout
                if requests_timeout is not None
                else self.requests_timeout
            )
            ssl_verify = ssl_verify if ssl_verify is not None else self.ssl_verify
            requests_session = (
                requests_session
                if requests_session is not None
                else self.requests_session
            )
            derive_encoding = (
                derive_encoding if derive_encoding is not None else self.derive_encoding
            )

            def _run_in_session(_requests_session: requests.Session):
                """
                perform the http(s) fetching in a nested function
                this allows us to use a context-manager for generated sessions
                which will handle unclosed socket issues in Python3
                """
                if response_peername__hook not in _requests_session.hooks["response"]:
                    _requests_session.hooks["response"].insert(
                        0, response_peername__hook
                    )  # must be first
                if derive_encoding:
                    if derive_encoding__hook not in _requests_session.hooks["response"]:
                        _requests_session.hooks["response"].append(
                            derive_encoding__hook
                        )
                try:
                    _resp = _requests_session.get(
                        url,
                        params=url_data,
                        headers=url_headers,
                        allow_redirects=allow_redirects,
                        verify=ssl_verify,
                        timeout=requests_timeout,
                        stream=True,
                    )
                except requests.exceptions.ChunkedEncodingError as exc:  # noqa: F841
                    # some servers drop a connection on the bad user-agent
                    if not url_headers:
                        raise
                    if not retry_dropped_without_headers:
                        raise
                    _resp = _requests_session.get(
                        url,
                        params=url_data,
                        headers={},
                        allow_redirects=allow_redirects,
                        verify=ssl_verify,
                        timeout=requests_timeout,
                        stream=True,
                    )
                return _resp

            if requests_session is None:
                with requests.Session() as requests_session:
                    resp = _run_in_session(requests_session)
            else:
                resp = _run_in_session(requests_session)

            self.response = resp
            self.peername = get_response_peername(resp)
            if resp.history:
                self.is_redirect = True
                # sometimes we encounter a circular redirect for auth
                self.is_redirect_unique = (
                    False if resp.url == resp.history[0].url else True
                )
                parsed_url_og = self.urlparse(url)
                parsed_url_dest = self.urlparse(resp.url)
                self.is_redirect_same_host = (
                    True if (parsed_url_og.netloc == parsed_url_dest.netloc) else False
                )
            else:
                self.is_redirect = False
                self.is_redirect_unique = False
            response_history = ResponseHistory(resp)

            # lowercase all of the HTTP headers for comparisons per RFC 2616
            self.response_headers = dict(
                (k.lower(), v) for k, v in resp.headers.items()
            )
            # stash this into the url actual too
            self.url_actual = self.parsed_result.metadata["_internal"]["url_actual"] = (
                resp.url
            )
            # stash the encoding
            self.parsed_result.metadata["_internal"]["encoding"] = html_encoding = (
                resp.encoding.lower() if resp.encoding else None
            )

            # if we're not following redirects, there could be an error here!
            if not allow_redirects:
                if resp.status_code in (301, 302, 307, 308):
                    header_location = resp.headers.get("location")
                    if header_location:
                        log.error("RedirectDetected | %s", self.url)
                        raise RedirectDetected(
                            location=header_location,
                            code=resp.status_code,
                            response=resp,
                            metadataParser=self,
                        )
                    log.error("NotParsableRedirect | %s", self.url)
                    raise NotParsableRedirect(
                        message="Status Code is redirect, but missing header",
                        code=resp.status_code,
                        metadataParser=self,
                    )

            if only_parse_http_ok and resp.status_code != 200:
                log.error(
                    "NotParsableFetchError | %s | status_code: %s",
                    self.url,
                    resp.status_code,
                )
                # log the history if it's there
                response_history.log(prefix="NotParsableFetchError History")

                raise NotParsableFetchError(
                    message="Status Code is not 200",
                    code=resp.status_code,
                    metadataParser=self,
                    response=resp,
                )

            # scoping; default to None
            content_type = None

            # pull the content_type from the headers
            if "content-type" in resp.headers:
                content_type = resp.headers["content-type"]
                # content type can have a character encoding in it...
                # the encoding may have been used
                content_type = [i.strip() for i in content_type.split(";")]
                content_type = content_type[0].lower()

            # exit quickly for content_types known to be NotParsable
            if content_type in self._content_types_noparse:
                if content_type == "application/json":
                    log.error("NotParsableJson | %s", self.url)
                    raise NotParsableJson(
                        "JSON header detected",
                        metadataParser=self,
                    )
                log.error("NotParsable | %s", self.url)
                raise NotParsable(
                    "NotParseable document detected! "
                    "content-type:'[%s]" % content_type,
                    metadataParser=self,
                )

            # if we don't have a content-type, let's try to do the right thing
            if (
                (content_type is None)
                or (content_type not in self._content_types_parse)
            ) and (not force_parse_invalid_content_type):
                log.error("NotParsable | %s | unknown filetype, response: ", self.url)
                raise NotParsable(
                    "I don't know how to parse this type of file! "
                    "content-type:'[%s]" % content_type,
                    metadataParser=self,
                )

            # okay, now we're safe to consume the request content
            # note that we're using `html` as `.text` which will be unicode coming in
            html = resp.text

        except requests.exceptions.RequestException as error:
            if hasattr(error, "response") and (error.response is not None):
                if TYPE_CHECKING:
                    assert error.response is not None
                self.response = error.response
                try:
                    assert self.response is not None  # mypy
                    self.peername = get_response_peername(self.response)
                    if self.response.history:
                        self.is_redirect = True
                except Exception:
                    pass
            log.error(
                "NotParsableFetchError | %s | `requests`: %s",
                self.url,
                error,
            )
            raise NotParsableFetchError(
                message="Error with `requests` library.  Inspect the `raised`"
                " attribute of this error.",
                raised=error,
                metadataParser=self,
            )
        if TYPE_CHECKING:
            assert html is not None
            assert html_encoding is not None
        return (html, html_encoding, response_history)

    def absolute_url(self, link: Optional[str] = None) -> Optional[str]:
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
            urlparser=self.urlparse,
        )

    def make_soup(self, html: str, **kwargs_bs) -> BeautifulSoup:
        """
        Turns an HTML string into a BeautifulSoup document.

        If your project requires a specific BeautifulSoup parser or failover,
        simply subclass `:class:MetadataParser` and implement this function.

        args:
            html: html doc as string
            **kwargs_bs: kwargs sent to BeautifulSoup

        example override:

            from metadata_parser import MetadataParser

            class MyParser(MetadataParser):
                def make_soup(self, html, **kwargs_bs):
                    doc = BeautifulSoup(html, **kwargs_bs)
                    return doc
        """
        try:
            doc = BeautifulSoup(html, "lxml", **kwargs_bs)
        except Exception as exc:  # noqa: F841
            if __debug__:
                log.debug("`BeautifulSoup` could not parse with `lxml`")
            doc = BeautifulSoup(html, "html.parser", **kwargs_bs)
        return doc

    def parse(
        self,
        html: str,
        html_encoding: Optional[str] = None,
        support_malformed: Optional[bool] = None,
        response_history: Optional[ResponseHistory] = None,
    ) -> None:
        """
        parses submitted `html`

        :param html: html document
        :type html: str
        :param html_encoding: html document encoding
        :type html_encoding: str, optional
        :param support_malformed: should malformed html be supported?
        :type support_malformed: bool, optional
        :param response_history: history of the url fetch_url
        :type response_history: class:`ResponseHistory`, optional
        """
        support_malformed = (
            support_malformed
            if support_malformed is not None
            else self.support_malformed
        )

        # stash this if we have it
        self.parsed_result.response_history = response_history

        if not isinstance(html, BeautifulSoup):
            kwargs_bs: Dict = {}
            # todo: use html_encoding
            if self.force_doctype:
                html = RE_doctype.sub("<!DOCTYPE html>", html)

            try:
                doc = self.make_soup(html, **kwargs_bs)
            except Exception as exc:
                log.error("Could not make soup of HTML: %s", exc)
                raise NotParsable(
                    "could not parse into BeautifulSoup", metadataParser=self
                )
            if not isinstance(doc, BeautifulSoup):
                log.error("Did not make soup of HTML, made %s" % type(doc))
                raise NotParsable(
                    "did not parse into BeautifulSoup", metadataParser=self
                )
        else:
            doc = html

        # stash the bs4 doc for further operations
        # do this now, otherwise it's a pain to debug if we return
        self.parsed_result.soup = doc

        # let's ensure that we have a real document...
        if not doc or not doc.html:
            if self.raise_on_invalid:
                log.error("InvalidDocument | no object")
                raise InvalidDocument("missing `doc` or `doc.html`")
            return

        # set the searchpath
        doc_searchpath: "_bs4_Tag" = doc.html  # bs4.element.Tag

        # shortcut
        parsed_result = self.parsed_result

        if self.search_head_only:
            if not doc.html.head:
                if self.raise_on_invalid:
                    log.error("InvalidDocument | no head")
                    raise InvalidDocument("missing `doc.html.head`")
                return
            doc_searchpath = doc.html.head  # bs4.element.Tag

        ogs = doc_searchpath.find_all("meta", attrs={"property": RE_prefix_opengraph})
        for og in ogs:
            try:
                parsed_result._add_discovered(
                    _target_container_key="og",
                    _target_key=og["property"][3:],
                    _raw_value=og["content"],
                )
            except (AttributeError, KeyError):
                pass
            except Exception as exc:
                if __debug__:
                    log.debug("Ran into a serious error parsing `og`: %s", exc)
                pass

        twitters = doc_searchpath.find_all("meta", attrs={"name": RE_prefix_twitter})
        for twitter in twitters:
            try:
                # for the deprecated "twitter:(label|data)" meta tags, we must use a 'value' attr
                # other tags use the "content" attr
                # some implementations uses "value" or "content" interchangeably though
                _key = twitter["name"][8:]
                if support_malformed or (_key.lower() in ("label", "data")):
                    _val = None  # scoping reminder
                    if _key.lower() in ("label", "data"):
                        _val = twitter.get("value", None)
                        if _val is None:
                            if support_malformed:
                                _val = twitter.get("content", None)
                    elif support_malformed:
                        # prefer `content` to `value`
                        _val = twitter.get("content", None)
                        if _val is None:
                            _val = twitter.get("value", None)
                else:
                    _val = twitter.get("content", None)

                # clients expect a string, not none
                # previous behavior was to exclude these items too
                if _val is None:
                    continue

                parsed_result._add_discovered(
                    _target_container_key="twitter", _target_key=_key, _raw_value=_val
                )

            except (AttributeError, KeyError):
                pass

        # pull the text off the title
        if doc_searchpath:
            try:
                if doc_searchpath.title is not None:
                    _title_text = doc_searchpath.title.text
                    if _title_text is not None:
                        _title_text = _title_text.strip()
                    if len(_title_text) > self.LEN_MAX_TITLE:
                        _title_text = _title_text[: self.LEN_MAX_TITLE]
                    parsed_result._add_discovered(
                        _target_container_key="page",
                        _target_key="title",
                        _raw_value=_title_text,
                    )
            except AttributeError:
                pass

        # is there an image_src?
        images = doc.find_all("link", attrs={"rel": RE_prefix_rel_img_src})
        if images:
            # we only use the first image on the page
            image = images[0]
            if image.has_attr("href"):
                _img_url = image["href"]
                parsed_result._add_discovered(
                    _target_container_key="page",
                    _target_key="image",
                    _raw_value=_img_url,
                )
            elif image.has_attr("content"):
                _img_url = image["content"]
                parsed_result._add_discovered(
                    _target_container_key="page",
                    _target_key="image",
                    _raw_value=_img_url,
                )
            else:
                pass

        # figure out the canonical url
        canonicals = doc.find_all("link", attrs={"rel": RE_canonical})
        if canonicals:
            # only use the first?
            canonical = canonicals[0]
            if canonical.has_attr("href"):
                _link = canonical["href"]
                parsed_result._add_discovered(
                    _target_container_key="page",
                    _target_key="canonical",
                    _raw_value=_link,
                )
            elif canonical.has_attr("content"):
                _link = canonical["content"]
                parsed_result._add_discovered(
                    _target_container_key="page",
                    _target_key="canonical",
                    _raw_value=_link,
                )
            else:
                pass

        # is there a shortlink?
        shortlinks = doc.find_all("link", attrs={"rel": RE_shortlink})
        for shortlink in shortlinks:
            if shortlink.has_attr("href"):
                _link = shortlink["href"]
                parsed_result._add_discovered(
                    _target_container_key="page",
                    _target_key="shortlink",
                    _raw_value=_link,
                )
            elif shortlink.has_attr("content"):
                _link = shortlink["content"]
                parsed_result._add_discovered(
                    _target_container_key="page",
                    _target_key="shortlink",
                    _raw_value=_link,
                )
            else:
                pass

        # pull out all the metadata
        meta = doc_searchpath.find_all(name="meta")
        for m in meta:
            try:
                k = None  # metadata key
                lbl = None  # metadata-label
                v = None  # metadata-value
                attrs = m.attrs
                # _k = k-candidate
                for _k in ("name", "property", "http-equiv"):
                    if _k in attrs:
                        k = _k
                        break

                if k:
                    lbl = attrs[k].strip()
                    if "content" in attrs:
                        v = attrs["content"]
                    elif "value" in attrs:
                        v = attrs["value"]
                    if (v is None) and (k == "name") and (lbl == "charset"):
                        v = attrs["charset"]
                    if v is not None:
                        if (len(lbl) > 3) and (lbl[:3].lower() in ("dc:", "dc.")):
                            _dc_formatted = {"content": v}
                            if "lang" in attrs:
                                _dc_formatted["lang"] = attrs["lang"]
                            if "scheme" in attrs:
                                _dc_formatted["scheme"] = attrs["scheme"]
                            self.parsed_result._add_discovered(
                                _target_container_key="dc",
                                _target_key=lbl[3:],
                                _raw_value=v,
                                _formatted_value=_dc_formatted,
                            )
                        else:
                            self.parsed_result._add_discovered(
                                _target_container_key="meta",
                                _target_key=lbl,
                                _raw_value=v,
                            )
                elif k is None:
                    if "charset" in attrs:
                        self.parsed_result._add_discovered(
                            _target_container_key="meta",
                            _target_key="charset",
                            _raw_value=attrs["charset"],
                        )
            except AttributeError:
                pass
        # optimize this away on cpython production servers
        if __debug__:
            if TESTING:
                pprint.pprint(self.parsed_result.__dict__)

    def get_url_scheme(self) -> Optional[str]:
        """try to determine the scheme"""
        candidate = self.url_actual or None
        if candidate is None:
            candidate = self.url or None
        if candidate:
            parsed = self.urlparse(candidate)
            if parsed.scheme:
                return parsed.scheme
        return None

    def upgrade_schemeless_url(
        self,
        url: str,
        field: Optional[str] = None,
    ) -> str:
        """
        urls can appear in html 3 ways:

        * Absolute -  https://example.com/path/to/foo
        * Relative -  /path/to/foo
        * Schemeless - //subdomain.example.com/path/to/foo

        if a url is schemeless, it should be treated as an absolute url on the same scheme.

        field is an optional paramter.
        if provided, it will be used to ensure the field of the url can be ugpraded.
        certain fields appear in `FIELDS_REQUIRE_HTTPS` and require an https scheme
        """
        if url[0:2] != "//":
            raise ValueError("not a schemeless url")
        scheme = self.get_url_scheme()
        if scheme:
            # field could be None
            if (field not in FIELDS_REQUIRE_HTTPS) or (scheme == "https"):
                url = "%s:%s" % (scheme, url)
        return url

    def get_fallback_url(
        self,
        require_public_netloc: bool = True,
        allow_localhosts: bool = True,
    ) -> Optional[str]:
        for _fallback_candndiate in (self.url_actual, self.url):
            if not _fallback_candndiate:
                continue
            if require_public_netloc or allow_localhosts:
                _parsed = is_url_valid(
                    _fallback_candndiate,
                    require_public_netloc=require_public_netloc,
                    allow_localhosts=allow_localhosts,
                    urlparser=self.urlparse,
                )
                if not _parsed:
                    continue
            # okay this works
            return _fallback_candndiate
        return None

    # --------------------------------------------------------------------------

    def get_url_canonical(
        self,
        require_public_global: bool = True,
        url_fallback: Optional[str] = None,
        allow_unicode_url: bool = True,
    ) -> Optional[str]:
        """
        this was originally part of `get_discrete_url`

        kwargs:
            require_public_global=True
            url_fallback=True
            allow_unicode_url=True
        """
        _candidates = self.parsed_result.get_metadatas("canonical", strategy=["page"])

        # get_metadatas returns a list, so find the first canonical item
        _candidates = [c for c in _candidates if c] if _candidates else []
        if not _candidates:
            return None
        canonical = _candidates[0]

        # does the canonical have valid characters?
        # some websites, even BIG PROFESSIONAL ONES, will put html in here.
        # amateurs.
        canonical_valid_chars = RE_rfc3986_valid_characters.match(canonical)
        if not canonical_valid_chars:
            if not allow_unicode_url:
                # exit early
                return None
            # try to fix it
            canonical = fix_unicode_url(
                canonical, encoding=self._response_encoding(), urlparser=self.urlparse
            )

            canonical_valid_chars = RE_rfc3986_valid_characters.match(canonical)
            if not canonical_valid_chars:
                return None

        # upgrade the url to a scheme?
        if canonical[0:2] == "//":
            field = "canonical"
            if field in self.schemeless_fields_upgradeable:
                canonical = self.upgrade_schemeless_url(canonical, field=field)

        if require_public_global:
            if url_fallback is None:
                # derive a fallback url, and ensure it is valid
                url_fallback = self.get_fallback_url(
                    require_public_netloc=True, allow_localhosts=False
                )
            if canonical and not is_url_valid(
                canonical,
                require_public_netloc=True,
                allow_localhosts=False,
                urlparser=self.urlparse,
            ):
                # try making it absolute
                canonical = url_to_absolute_url(
                    canonical,
                    url_fallback=url_fallback,
                    require_public_netloc=True,
                    allow_localhosts=False,
                    urlparser=self.urlparse,
                )
                if not is_url_valid(
                    canonical,
                    require_public_netloc=True,
                    allow_localhosts=False,
                    urlparser=self.urlparse,
                ):
                    # set to NONE if invalid
                    canonical = None
        return canonical

    def get_url_opengraph(
        self,
        require_public_global: bool = True,
        url_fallback: Optional[str] = None,
        allow_unicode_url: bool = True,
    ) -> Optional[str]:
        """
        this was originally part of `get_discrete_url`

        kwargs:
            require_public_global=True
            url_fallback=None
            allow_unicode_url=True
        """
        _candidates = self.parsed_result.get_metadatas("url", strategy=["og"])
        # get_metadatas returns a list, so find the first og item
        _candidates = [c for c in _candidates if c] if _candidates else []
        if not _candidates:
            return None
        og = _candidates[0]

        # does the og have valid characters?
        # some websites, even BIG PROFESSIONAL ONES, will put html in here.
        # idiots.
        og_valid_chars = RE_rfc3986_valid_characters.match(og)
        if not og_valid_chars:
            if not allow_unicode_url:
                # exit early
                return None
            # try to fix it
            og = fix_unicode_url(
                og, encoding=self._response_encoding(), urlparser=self.urlparse
            )
            og_valid_chars = RE_rfc3986_valid_characters.match(og)
            if not og_valid_chars:
                return None

        # upgrade the url to a scheme?
        if og[0:2] == "//":
            field = "og:url"
            if field in self.schemeless_fields_upgradeable:
                og = self.upgrade_schemeless_url(og, field=field)

        if require_public_global:
            if url_fallback is None:
                # derive a fallback url, and ensure it is valid
                url_fallback = self.get_fallback_url(
                    require_public_netloc=True, allow_localhosts=False
                )
            if og and not is_url_valid(
                og,
                require_public_netloc=True,
                allow_localhosts=False,
                urlparser=self.urlparse,
            ):
                # try making it absolute
                og = url_to_absolute_url(
                    og,
                    url_fallback=url_fallback,
                    require_public_netloc=True,
                    allow_localhosts=False,
                    urlparser=self.urlparse,
                )
                if not is_url_valid(
                    og,
                    require_public_netloc=True,
                    allow_localhosts=False,
                    urlparser=self.urlparse,
                ):
                    # set to NONE if invalid
                    og = None
        return og

    # --------------------------------------------------------------------------

    def get_discrete_url(
        self,
        og_first: bool = True,
        canonical_first: bool = False,
        require_public_global: bool = True,
        allow_unicode_url: bool = True,
    ) -> Optional[str]:
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
            allow_unicode_url=True
        """
        _ts = (og_first, canonical_first)
        if not any(_ts) or all(_ts):
            raise ValueError("submit one and only one of (og_first, canonical_first")

        url_fallback = None
        if require_public_global:
            url_fallback = self.get_fallback_url(
                require_public_netloc=True, allow_localhosts=False
            )

        if og_first:
            ordering = ("og", "canonical")
        elif canonical_first:
            ordering = ("canonical", "og")

        for source in ordering:
            url = None
            if source == "og":
                url = self.get_url_opengraph(
                    require_public_global=require_public_global,
                    url_fallback=url_fallback,
                    allow_unicode_url=allow_unicode_url,
                )
            elif source == "canonical":
                url = self.get_url_canonical(
                    require_public_global=require_public_global,
                    url_fallback=url_fallback,
                    allow_unicode_url=allow_unicode_url,
                )
            if url:
                return url

        return self.absolute_url()

    # --------------------------------------------------------------------------

    def get_metadata_link(
        self,
        field: str,
        strategy: Union[List[str], str, None] = None,
        allow_encoded_uri: bool = False,
        require_public_global: bool = True,
    ) -> Optional[str]:
        """sometimes links are bad; this tries to fix them.  most useful for meta images

        args:
            field

        kwargs:
            strategy=None
                'all' or List ['og', 'dc', 'meta', 'page', 'twitter', ]
            allow_encoded_uri=False
            require_public_global=True

        if `require_public_global` is True, this will try to correct
            the data (relative to absolute) or reset to None.  This option will
            also require the fallback url to be on the public internet and not a
            localhost value.
        """
        _candidates = self.parsed_result.get_metadatas(field, strategy=strategy)
        _candidates = [c for c in _candidates if c] if _candidates else []
        if not _candidates:
            return None
        # `_value` will be our raw value
        _value = _candidates[0]

        # `value` will be our clean value
        # remove whitespace, because some bad blogging platforms add in whitespace by printing elements on multiple lines. d'oh!
        # this also up data:image and normal links
        value = RE_whitespace.sub("", _value)

        # it's possible for an encoded URI to be an image
        # if that is the case, don't return it (this is `get_metadata_LINK`)
        if value[:11].lower().startswith("data:image/"):
            if allow_encoded_uri:
                return value
            return None

        # it is possible for a declared url to not have rfc valid characters
        # sometimes you'll find HTML documents in here. serious!
        is_valid_chars = RE_rfc3986_valid_characters.match(value)
        if not is_valid_chars:
            return None

        # upgrade the url to a scheme?
        if value[0:2] == "//":
            if field in self.schemeless_fields_upgradeable:
                value = self.upgrade_schemeless_url(value, field=field)
            if field in self.schemeless_fields_disallow:
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
            urlparser=self.urlparse,
        ):
            return value

        # fallback url is used to drop to the domain
        url_fallback = self.get_fallback_url(
            require_public_netloc=_require_public_netloc,
            allow_localhosts=_allow_localhosts,
        )

        # try making it absolute
        value_fixed = url_to_absolute_url(
            value,
            url_fallback=url_fallback,
            require_public_netloc=_require_public_netloc,
            allow_localhosts=_allow_localhosts,
            urlparser=self.urlparse,
        )
        if value_fixed:
            if is_url_valid(
                value_fixed,
                require_public_netloc=_require_public_netloc,
                allow_localhosts=_allow_localhosts,
                urlparser=self.urlparse,
            ):
                # last check on the field...
                # only needed here, because we're using the url_fallback
                if field in FIELDS_REQUIRE_HTTPS:
                    parsed_fixed_url = self.urlparse(value_fixed)
                    if parsed_fixed_url.scheme != "https":
                        return None
                return value_fixed

        return None
