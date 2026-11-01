# Session cleanup proof

`cloud-verification.json` is the result of the independently reviewed, read-only
verifier after removal. Its source is retained as `verify-final-cleanup.py` and
bound by SHA-256 in `summary.json`. The verifier pins the private ownership plan
SHA-256, checks 26 absence conditions, and separately checks that the shared
VPC, NAT gateway and route tables still exist. An API error is a failed check.

The unchanged original verifier and its first result are also retained. Its
instance-list check failed because EC2 had stopped listing the Windows host
already verified terminated at 05:09 UTC. The final verifier adds a narrow check
for that exact ID: successful empty exact-ID and filtered queries, bound to the
original retirement proof by SHA-256. All other checks are unchanged. Five offline
controls covered terminal, absent, running and inaccessible cases; inaccessible
queries still fail. The original failed result is not relabelled as a pass.

`local-staging-verification.json` records absence of only the explicitly reviewed
current-session credential and artifact staging paths. The historical discovery
list was not a deletion manifest. Default Azure/AWS configuration, repository,
private metadata and audit scripts are preserved.

The earlier Windows instance/volume retirement and security-test cleanup are
separate historical scopes. This proof covers the final main campaign. It is
not an account-wide, all-region billing audit. The source verifier requires the
private ownership plan and authenticated cloud access; the check below verifies
the retained evidence offline and makes no new live-cloud claim.

`removal-attempts.json` preserves the nonempty-bucket stack failure and the local
quiet-response parsing failure, followed by successful retries. The retry listed
zero remaining versions/delete markers before deleting the bucket. The initial
batch size was not retained, so no exact deleted-version count is claimed.

From the evidence directory, run:

```sh
python3 - <<'PY'
import hashlib
import json
from pathlib import Path

root = Path.cwd().resolve()
summary = json.loads((root / 'summary.json').read_text())
cleanup = summary['cleanup']
loaded = {}
for name, record in cleanup['evidence'].items():
    path = (root / record['file']).resolve()
    assert root in path.parents and not path.is_symlink()
    data = path.read_bytes()
    assert len(data) == record['bytes']
    assert hashlib.sha256(data).hexdigest() == record['sha256']
    if path.suffix != '.py':
        loaded[name] = json.loads(data)
cloud, local = loaded['cloud'], loaded['local']
assert cloud['inventoryPlanSha256'] == 'daf0efcd316034b79207a6fa4fa375ec3b30c1ea33a1358e275350a223d2151e'
assert cloud['runId'] == local['runId'] == summary['runId']
assert len(cloud['checks']) == 26 and len(cloud['preservationChecks']) == 3
checks = cloud['checks'] + cloud['preservationChecks']
assert len({item['check'] for item in checks}) == 29
assert all(item['passed'] is True and 'errorCategory' not in item for item in checks)
assert cloud['cleanupVerified'] is True and cloud['sharedInfrastructurePresent'] is True
original = loaded['originalVerification']
assert original['cleanupVerified'] is False
assert [item['check'] for item in original['checks'] if not item['passed']] == ['aws-instances']
instance = next(item['evidence'] for item in cloud['checks'] if item['check'] == 'aws-instances')
assert instance['absentAfterVerifiedRetirement'] == ['i-058c97f8db6c0dbbf']
assert instance['exactIdQuerySucceededAndEmpty'] and instance['filteredQuerySucceededAndEmpty']
assert instance['priorRetirementProofSha256'] == '638c6dfb46d5e7eeaadd85098c65314a0ff1ab7c7f710679201432a07cbe292e'
assert local['checks'] and all(item['absent'] is True for item in local['checks'])
assert local['credentialStagingRemoved'] is True and not local['errors']
assert cleanup['fullCampaignCleanup'] is True
assert summary['productionReadyClaim'] is False
print(json.dumps({'cloudAbsenceChecks': 26, 'sharedPresenceChecks': 3,
                  'localStagingChecks': len(local['checks']),
                  'offlineCleanupProofVerified': True}))
PY
```
