import os

# ==============================================================================

# defaults
DISABLE_TLDEXTRACT = bool(
    int(os.environ.get("METADATA_PARSER__DISABLE_TLDEXTRACT", "0"))
)
DUMMY_URL = os.environ.get(
    "METADATA_PARSER__DUMMY_URL", "http://example.com/index.html"
)
ENCODING_FALLBACK = os.environ.get("METADATA_PARSER__ENCODING_FALLBACK", "ISO-8859-1")
FUTURE_BEHAVIOR = bool(int(os.getenv("METADATA_PARSER_FUTURE", "0")))
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
