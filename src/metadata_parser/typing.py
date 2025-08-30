# stdlib
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING
from typing import TypeVar
from typing import Union

# pypi
from typing_extensions import Protocol  # py38

if TYPE_CHECKING:
    from urllib.parse import ParseResult

    from requests import Response

    from . import ResponseHistory
    from .utils import DummyResponse

    # from requests.structures import CaseInsensitiveDict

# ==============================================================================

T = TypeVar("T")

# TYPE_ENCODER = Callable[[str, Optional[str]], str]  # def encode(value, strategy)
TYPE_ENCODER = Callable[
    [str, Optional[str]], Union[str, Dict]
]  # def encode(value, strategy)
TYPE_REQUESTS_TIMEOUT = Optional[
    Union[int, float, Tuple[int, int], Tuple[float, float]]
]
TYPE_URL_FETCH = Tuple[str, str, "ResponseHistory"]
TYPE_URLPARSE = Callable[[str], "ParseResult"]
TYPES_PEERNAME = Tuple[str, int]  # (ip, port)
TYPES_RESPONSE = Union["Response", "DummyResponse", T]
TYPES_STRATEGY = Union[List[str], str, None]


"""
# TYPES_RESPONSE_EXTENDED = Union["TYPES_RESPONSE", "_SupportsContent", "T"]
class _SupportsContent(Protocol):

    _encoding_content: Optional[str]
    _encoding_fallback: str
    _encoding_headers: Optional[str]
    content: str
    encoding: Optional[str]
    headers: "CaseInsensitiveDict"
"""


class _UrlParserCacheable(Protocol):
    urlparse: TYPE_URLPARSE
