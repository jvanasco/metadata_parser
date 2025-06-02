# stdlib
from typing import Callable
from typing import Dict
from typing import List
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING
from typing import Union

# pypi
from typing_extensions import Protocol  # py38

if TYPE_CHECKING:
    import requests
    from urllib.parse import ParseResult
    from . import DummyResponse
    from . import ResponseHistory

# ==============================================================================

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
TYPES_RESPONSE = Union["DummyResponse", "requests.Response"]
TYPES_STRATEGY = Union[List[str], str, None]


class _UrlParserCacheable(Protocol):
    urlparse: TYPE_URLPARSE
