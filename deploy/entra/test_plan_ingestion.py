import json
import unittest
from plan_ingestion import create_plan


class IngestionPlanTests(unittest.TestCase):
    def test_deterministic_machine_identity_plan(self):
        first = create_plan("security-law", "australiaeast", "bower", managed_identity=True)
        self.assertEqual(first, create_plan("security-law", "australiaeast", "bower", managed_identity=True))
        parameters, plan = map(json.loads, first)
        self.assertTrue(parameters["parameters"]["createIngestIdentity"]["value"])
        self.assertEqual(plan["mode"], "plan-only")
        self.assertFalse(plan["azureMutationsPerformed"])
        other = create_plan("another-law", "australiaeast", "bower", managed_identity=True)
        self.assertNotEqual(plan["planSha256"], json.loads(other[1])["planSha256"])

    def test_federation_is_exact_optional_and_requires_new_identity(self):
        issuer = "https://issuer.example.test/tenant/"
        subject = "system:serviceaccount:security:bower"
        parameters, plan = create_plan("security-law", "australiaeast", "bower", managed_identity=True,
                                       federation_issuer=issuer, federation_subject=subject)
        self.assertEqual(json.loads(parameters)["parameters"]["federationIssuer"]["value"], issuer)
        self.assertTrue(json.loads(plan)["federationPlanned"])
        for invalid in [
            {"federation_issuer": issuer},
            {"federation_subject": subject},
            {"federation_issuer": "http://issuer.example.test", "federation_subject": subject},
            {"federation_issuer": "https://user:secret@example.test", "federation_subject": subject},
            {"federation_issuer": issuer, "federation_subject": "system:serviceaccount:*"},
            {"federation_issuer": issuer, "federation_subject": "bad\nsubject"},
        ]:
            with self.assertRaises(ValueError):
                create_plan("security-law", "australiaeast", "bower", managed_identity=True, **invalid)
        with self.assertRaises(ValueError):
            create_plan("security-law", "australiaeast", "bower", principal="11111111-2222-3333-4444-555555555555",
                        federation_issuer=issuer, federation_subject=subject)

    def test_existing_identity_and_invalid_inputs(self):
        principal = "11111111-2222-3333-4444-555555555555"
        parameters, _ = create_plan("security-law", "australiaeast", "bower", principal=principal)
        self.assertEqual(json.loads(parameters)["parameters"]["ingestPrincipalObjectId"]["value"], principal)
        for kwargs in [{}, {"principal": "invalid"}, {"principal": principal, "managed_identity": True}]:
            with self.assertRaises(ValueError):
                create_plan("security-law", "australiaeast", "bower", **kwargs)
        with self.assertRaises(ValueError):
            create_plan("../wrong", "australiaeast", "bower", managed_identity=True)


if __name__ == "__main__":
    unittest.main()
