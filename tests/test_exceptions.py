# stdlib
import unittest

# local
from metadata_parser.exceptions import SecurityPolicyViolation
from metadata_parser.exceptions import SecurityPolicyViolation_URL
from metadata_parser.exceptions import SecurityPolicyViolation_URL_Initial
from metadata_parser.exceptions import SecurityPolicyViolation_URL_Redirect


class TestSecurityPolicyExceptions(unittest.TestCase):
    def test_url_variants_are_caught_by_parent_handlers(self):
        for exception_type in (
            SecurityPolicyViolation_URL_Initial,
            SecurityPolicyViolation_URL_Redirect,
        ):
            for parent_type in (
                SecurityPolicyViolation_URL,
                SecurityPolicyViolation,
            ):
                with self.subTest(exception=exception_type, parent=parent_type):
                    error = exception_type("URL rejected")
                    with self.assertRaises(parent_type) as caught:
                        raise error
                    self.assertIs(caught.exception, error)
