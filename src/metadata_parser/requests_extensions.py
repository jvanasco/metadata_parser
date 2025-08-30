import _socket  # noqa: I201

# stdlib
import cgi  # noqa: I202
import logging
import socket
from typing import Any
from typing import Optional
from typing import Tuple
from typing import TYPE_CHECKING

# pypi
from requests_toolbelt.utils.deprecated import get_encodings_from_content

# local
from . import config
from .exceptions import AllowableError
from .utils import safe_sample

if TYPE_CHECKING:
    from requests.structures import CaseInsensitiveDict

    from .typing import TYPES_PEERNAME
    from .typing import TYPES_RESPONSE


# ==============================================================================

log = logging.getLogger("metdata_parser")

# ------------------------------------------------------------------------------


# peername hacks
# only use for these stdlib packages
# eventually will not be needed thanks to upstream changes in `requests`
_compatible_sockets: Tuple[Any, ...]
try:
    _compatible_sockets = (
        _socket.socket,
        socket._socketobject,  # type: ignore[attr-defined]
    )
except AttributeError:
    _compatible_sockets = (_socket.socket,)  # type: ignore[no-redef]


def derive_encoding__hook(resp: Any, *args, **kwargs) -> None:
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
        assert hasattr(resp, "_encoding_content")
        assert hasattr(resp, "_encoding_fallback")
        assert hasattr(resp, "_encoding_headers")

    resp._encoding_content = None
    resp._encoding_fallback = config.ENCODING_FALLBACK
    # modified version, returns `None` if no charset available
    resp._encoding_headers = get_encoding_from_headers(resp.headers)
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


def get_encoding_from_headers(headers: "CaseInsensitiveDict") -> Optional[str]:
    """
    Returns encodings from given HTTP Header Dict.

    :param headers: dictionary to extract encoding from.
    :rtype: str

    `requests.get("http://example.com").headers`
        should be `requests.structures.CaseInsensitiveDict`

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


def get_response_peername(
    resp: Any,
) -> Optional["TYPES_PEERNAME"]:
    """
    used to get the peername (ip+port) data from the request
    if a socket is found, caches this onto the request object

    IMPORTANT. this must happen BEFORE any content is consumed.

    `response` is really `requests.models.Response`

    This will UPGRADE the response object to have the following attribute:

        * _mp_peername
    """
    # if not isinstance(resp, Response) and not isinstance(resp, DummyResponse):
    #    # raise AllowableError("Not a HTTPResponse")
    #    log.debug("Not a supported HTTPResponse | %s", resp)
    #    log.debug("-> received a type of: %s", type(resp))
    #    return None

    if hasattr(resp, "_mp_peername"):
        return resp._mp_peername

    def _get_socket() -> Optional[socket.socket]:
        # only socket to `requests.Response`
        # if not isinstance(resp, "Response"):
        if not hasattr(resp, "raw"):
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

    _mp_peername: Optional["TYPES_PEERNAME"] = None
    sock = _get_socket()
    if sock is not None:
        # only cache if we have a sock
        # we may want/need to call again
        _mp_peername = sock.getpeername()
    setattr(resp, "_mp_peername", _mp_peername)  # type: ignore[union-attr]
    return _mp_peername


# ------------------------------------------------------------------------------


def response_peername__hook(resp: "TYPES_RESPONSE", *args, **kwargs) -> None:
    get_response_peername(resp)
    # do not return anything
