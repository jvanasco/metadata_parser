# stdlib
from typing import Optional
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    import requests
    from . import MetadataParser
    from .typing import TYPES_RESPONSE

# ==============================================================================


class AllowableError(Exception):
    pass


class InvalidDocument(Exception):
    message: str

    def __init__(self, message: str = ""):
        self.message = message

    def __str__(self) -> str:
        return "InvalidDocument: %s" % (self.message)


class NotParsable(Exception):
    code: Optional[int]
    metadataParser: Optional["MetadataParser"]
    raised: Optional["requests.exceptions.RequestException"]
    response: Optional["TYPES_RESPONSE"]

    def __init__(
        self,
        message: str = "",
        raised: Optional["requests.exceptions.RequestException"] = None,
        code: Optional[int] = None,
        metadataParser: Optional["MetadataParser"] = None,
        response: Optional["TYPES_RESPONSE"] = None,
    ):
        self.code = code
        self.message = message
        self.metadataParser = metadataParser
        self.raised = raised
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


class RedirectDetected(Exception):
    """
    Raised if a redirect is detected
    Instance properties:

    ``location``: redirect location
    ``code``: status code of the response
    ``response``: actual response object
    """

    code: Optional[int]
    location: str
    metadataParser: Optional["MetadataParser"]
    response: Optional["TYPES_RESPONSE"]

    def __init__(
        self,
        location: str = "",
        code: Optional[int] = None,
        response: Optional["TYPES_RESPONSE"] = None,
        metadataParser: Optional["MetadataParser"] = None,
    ):
        self.code = code
        self.location = location
        self.metadataParser = metadataParser
        self.response = response
