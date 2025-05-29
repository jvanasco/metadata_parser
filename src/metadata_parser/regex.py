import re

# ==============================================================================

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
