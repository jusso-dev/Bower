#!/bin/bash
set -euo pipefail
umask 077
aws s3 cp "s3://$BOWER_LAB_BUCKET/artifacts/manifest.json" /opt/bower-lab/manifest.json --only-show-errors
aws s3 cp "s3://$BOWER_LAB_BUCKET/artifacts/verify.py" /opt/bower-lab/verify.py --only-show-errors
python3 - <<'PY'
import hashlib,json
from pathlib import Path
root=Path('/opt/bower-lab')
if hashlib.sha256((root/'verify.py').read_bytes()).hexdigest()!=json.loads((root/'manifest.json').read_text())['files']['verify.py']:
    raise ValueError('Verifier checksum mismatch')
PY
# Use a distinct phase for each saved verification; never overwrite a failed deadline report.
python3 /opt/bower-lab/verify.py --phase "${BOWER_LAB_PHASE:-baseline}"
