# stdlib
import datetime
from html import unescape as html_unescape
import logging
from typing import AnyStr
from typing import Callable
from typing import List
from typing import Optional
from typing import TYPE_CHECKING
from typing import Union
import unicodedata
from urllib.parse import quote as url_quote
from urllib.parse import unquote as url_unquote
from urllib.parse import urlparse
from urllib.parse import urlunparse
import warnings

# pypi
from requests.structures import CaseInsensitiveDict
from requests_toolbelt.utils.deprecated import get_encodings_from_content

# local
from . import config
from .regex import RE_rfc3986_valid_characters


if TYPE_CHECKING:
    from urllib.parse import ParseResult


# ==============================================================================

log = logging.getLogger("metdata_parser")

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
        content: Optional[AnyStr] = None,
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
        self.default_encoding = default_encoding or config.ENCODING_FALLBACK
        # second phase cleanup
        if not encoding:
            self.encoding = self.default_encoding
        # end `encoding` block


def decode_html(text: str) -> str:
    """
    helper function to decode text that has both HTML and non-ascii characters
    """
    text = encode_ascii(html_unescape(text))
    return text


def encode_ascii(text: str) -> str:
    """
    helper function to force ascii;
    some edge-cases have unicode line breaks in titles/etc.
    """
    if not text:
        text = ""
    _as_bytes = unicodedata.normalize("NFKD", text).encode("ascii", "ignore")
    _as_str = _as_bytes.decode("utf-8", "ignore")
    return _as_str


def fix_unicode_url(
    url: str,
    encoding: Optional[str] = None,
    urlparser: Callable[[str], "ParseResult"] = urlparse,
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


def safe_sample(source: Union[str, bytes]) -> bytes:
    if isinstance(source, bytes):
        _sample = source[:1024]
    else:
        # this block can cause an error on PY3 depending on where the data came
        # from such as what the source is (from a request vs a document/test)
        # thanks, @keyz182 for the PR/investigation
        # https://github.com/jvanasco/metadata_parser/pull/16
        _sample = (source.encode())[:1024]
    return _sample


def warn_future(message: str) -> None:
    warnings.warn(message, FutureWarning, stacklevel=2)
    if config.FUTURE_BEHAVIOR:
        raise ValueError(message)


def warn_user(message: str) -> None:
    warnings.warn(message, UserWarning, stacklevel=2)
