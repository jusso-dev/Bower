import importlib.util
from pathlib import Path
import unittest

spec = importlib.util.spec_from_file_location("relp_cleanup_audit", Path(__file__).resolve().parents[1] / "monitoring/relp-cleanup-audit.py")
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)


class RelpCleanupAuditTests(unittest.TestCase):
    def test_only_exact_not_found_codes_prove_absence(self):
        cases = [
            ("An error occurred (InvalidInstanceID.NotFound) when calling the DescribeInstances operation", ("InvalidInstanceID.NotFound",), True),
            ("An error occurred (UnauthorizedOperation) when calling the DescribeInstances operation", ("InvalidInstanceID.NotFound",), False),
            ("An error occurred (RequestLimitExceeded) when calling the DescribeVolumes operation", ("InvalidVolume.NotFound",), False),
            ("An error occurred (ExpiredToken) when calling the GetRole operation", ("NoSuchEntity",), False),
            ("An error occurred (AccessDenied) when calling the GetRole operation", ("NoSuchEntity",), False),
            ("An error occurred (404) when calling the HeadBucket operation: Not Found", ("404", "NoSuchBucket"), True),
            ("An error occurred (403) when calling the HeadBucket operation: Forbidden", ("404", "NoSuchBucket"), False),
            ('ERROR: Not Found({"error":{"code":"Request_ResourceNotFound"}})', ("Request_ResourceNotFound",), True),
            ('ERROR: Forbidden({"error":{"code":"Authorization_RequestDenied"}})', ("Request_ResourceNotFound",), False),
            ("Could not connect to the endpoint URL", ("InvalidGroup.NotFound",), False),
            # Secrets: only not-found proves deletion; a scheduled deletion still describes.
            ("An error occurred (ResourceNotFoundException) when calling the DescribeSecret operation", ("ResourceNotFoundException",), True),
            ("An error occurred (AccessDeniedException) when calling the DescribeSecret operation", ("ResourceNotFoundException",), False),
        ]
        for err, codes, absent in cases:
            with self.subTest(err=err):
                self.assertIs(absent, module.gone(255, err, *codes))
        # A successful call is never "gone"; the caller inspects its result instead.
        self.assertFalse(module.gone(0, "", "InvalidInstanceID.NotFound"))
        self.assertEqual("unclassified", module.error_code("Could not connect to the endpoint URL"))


if __name__ == "__main__":
    unittest.main()
