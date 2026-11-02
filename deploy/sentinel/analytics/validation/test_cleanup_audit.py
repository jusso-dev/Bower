"""Cleanup audit: only empty listings and exact not-found codes count as absence."""

import json
import os
import re
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import cleanup_audit  # noqa: E402

NAME = "bower-test-20261102-000000-ingest"
STATE = {"runId": "bower-test-20261102-000000", "group": "rg-bower-test-20261102-000000", "workspaceName": "law-test",
         "identities": {"ingest": {"name": NAME, "appId": "a", "objectId": "o", "principalId": "p"}}}
GONE = {
    "group exists": (0, False, ""),
    "resource list": (0, [], ""),
    "workspace show": (3, None, "ERROR: (ResourceGroupNotFound) Resource group was not found."),
    "list-deleted-workspaces": (0, [], ""),
    "app list": (0, [], ""),
    "sp list": (0, [], ""),
    "deletedItems/o": (1, None, "ERROR: Not Found({\"error\":{\"code\":\"Request_ResourceNotFound\"}})"),
    "deletedItems/p": (1, None, "ERROR: Not Found({\"error\":{\"code\":\"Request_ResourceNotFound\"}})"),
    "role assignment": (0, [], ""),
}


def fake_az(responses):
    def az(*args):
        command = " ".join(args)
        for key, value in responses.items():
            if all(part in command for part in key.split(" ")):
                return value
        raise AssertionError("unexpected az call: " + command)
    return az


def run(overrides):
    responses = {**GONE, **overrides}
    original = cleanup_audit.az
    cleanup_audit.az = fake_az(responses)
    try:
        with tempfile.TemporaryDirectory() as directory:
            state, output = os.path.join(directory, "state.json"), os.path.join(directory, "cleanup.json")
            with open(state, "w", encoding="utf-8") as handle:
                json.dump(STATE, handle)
            code = cleanup_audit.main(["--state", state, "--subscription", "s", "--output", output])
            with open(output, encoding="utf-8") as handle:
                return code, {item["check"]: item for item in json.load(handle)["checks"]}
    finally:
        cleanup_audit.az = original


class CleanupAuditTests(unittest.TestCase):
    def test_error_code_names_only_recognised_not_found_codes(self):
        for stderr, expected in [
            ("ERROR: (ResourceGroupNotFound) Resource group 'x' could not be found.", "ResourceGroupNotFound"),
            ('{"error":{"code":"Request_ResourceNotFound"}}', "Request_ResourceNotFound"),
            ("ERROR: (ResourceNotFound) The Resource was not found.", "ResourceNotFound"),
            ("ERROR: (AuthorizationFailed) The client does not have authorization.", "unrecognised-error"),
            ("", "unrecognised-error"),
            (None, "unrecognised-error"),
        ]:
            self.assertEqual(expected, cleanup_audit.error_code(stderr), stderr)

    def test_everything_gone_passes(self):
        code, checks = run({})
        self.assertEqual(0, code)
        self.assertTrue(all(item["absent"] for item in checks.values()))
        self.assertEqual(9, len(checks))

    def test_absence_is_proven_only_by_empty_listings_and_exact_codes(self):
        cases = [
            # (override, check name pattern, expected absent)
            ({"app list": (0, [{"displayName": NAME + "-2"}], "")}, "application", True),  # prefix collision
            ({"app list": (0, [{"displayName": NAME}], "")}, "application", False),
            ({"app list": (1, None, "ERROR: (AuthorizationFailed) denied")}, "application", False),
            ({"sp list": (0, [{"displayName": NAME + "-other"}], "")}, "service principal", True),
            ({"resource list": (0, [{"id": "x"}], "")}, "resources tagged", False),
            ({"group exists": (0, True, "")}, "^resource group", False),
            ({"workspace show": (1, None, "ERROR: (AuthorizationFailed) denied")}, "^workspace law-test$", False),
            ({"workspace show": (0, {"id": "w"}, "")}, "^workspace law-test$", False),
            ({"deletedItems/o": (1, None, "ERROR: Bad Request")}, "deleted-items objectId", False),
            ({"deletedItems/o": (0, {"id": "o"}, "")}, "deleted-items objectId", False),
            ({"list-deleted-workspaces": (0, [{"name": "law-test", "id": "/subscriptions/s/resourceGroups/rg-bower-test-20261102-000000/providers/x/law-test"}], "")},
             "soft-deleted workspace", False),
            ({"list-deleted-workspaces": (0, [{"name": "law-test", "id": "/subscriptions/s/resourceGroups/rg-other/providers/x/law-test"}], "")},
             "soft-deleted workspace", True),
        ]
        for override, fragment, absent in cases:
            code, checks = run(override)
            matched = [item for name, item in checks.items() if re.search(fragment, name)]
            self.assertEqual(1, len(matched), fragment)
            self.assertEqual(absent, matched[0]["absent"], (override, fragment))
            self.assertEqual(0 if absent else 1, code, override)
            if not absent and next(iter(override.values()))[0]:
                self.assertIn("errorCode", matched[0])


if __name__ == "__main__":
    unittest.main()
