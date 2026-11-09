# Verified ASVS and ISM identifiers

Bower content may only cite OWASP ASVS and ASD ISM identifiers from two verified lists. Each
list was built from the official source and records where it came from:

| List | Source | Pinned |
|---|---|---|
| [`verified/asvs-5.0.0-logging.json`](verified/asvs-5.0.0-logging.json) | [OWASP/ASVS](https://github.com/OWASP/ASVS) release `v5.0.0_release`, asset `OWASP_Application_Security_Verification_Standard_5.0.0_en.flat.json` | Tag commit `5cf9b032440be53ce345ab3c130fda46ba1ce7a2`, asset SHA-256 `8201b20e…2311` |
| [`verified/ism-2026-09-logging.json`](verified/ism-2026-09-logging.json) | ISM September 2026, [OSCAL catalogue `v2026.09.4`](https://www.cyber.gov.au/ism/oscal/v2026.09.4) on cyber.gov.au | Catalogue SHA-256 `237ea093…f12d` |

Each entry holds the ID, the exact requirement or control text, and the ASVS level or ISM
revision. The ASVS list covers all 17 V16 (Security Logging and Error Handling) requirements
plus 25 logging-relevant requirements from V2, V4, V6, V7, V8, V13, V14 and V15. The ISM list
covers every control in the event logging sections, plus single logging controls from the
system access, software development and procurement guidelines.

In the September 2026 ISM, event logging sits under *Guidelines for security assurance >
Security monitoring* (policy, centralised facility, event log details, monitoring, threat
hunting and retention). System-specific logging controls sit elsewhere, for example
ISM-1537 (databases), ISM-1911 (software), ISM-1978 (server applications) and ISM-1963
(network devices).

## Rules

- Cite only IDs in these lists. Never cite ASVS 4.x IDs: 5.0 renumbered every chapter.
- `ComplianceCitationTests` scans docs, packs, policies, rules, deploy content, examples and
  source for `V<chapter>.<section>.<requirement>` and `ISM-<nnnn>` and fails on any ID that
  isn't in the lists.
- To add an ID, add it to `tools/compliance/verify_sources.py`, then regenerate:

```bash
python3 -I tools/compliance/verify_sources.py write   # downloads the pinned sources
python3 -I tools/compliance/verify_sources.py check   # fails if the lists drift
```

The script uses the standard library only, downloads into a fresh temporary directory, and
refuses a source whose SHA-256 doesn't match the pinned value. A new ISM release needs a
new pinned version and hash, and a review of every page that cites the ISM.
