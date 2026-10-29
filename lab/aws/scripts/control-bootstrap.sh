#!/bin/bash
set -euo pipefail
umask 077
install -d -m 0700 /opt/bower-lab
aws s3 cp "s3://$BOWER_LAB_BUCKET/artifacts/control.py" /opt/bower-lab/control.py --only-show-errors
aws s3 cp "s3://$BOWER_LAB_BUCKET/artifacts/manifest.json" /opt/bower-lab/manifest.json --only-show-errors
python3 - <<'VERIFY'
import hashlib,json
from pathlib import Path
root=Path('/opt/bower-lab')
manifest=json.loads((root/'manifest.json').read_text())
if hashlib.sha256((root/'control.py').read_bytes()).hexdigest()!=manifest['files']['control.py']:
    raise ValueError('Bootstrap checksum mismatch')
VERIFY
python3 /opt/bower-lab/control.py
