#!/bin/bash
set -euo pipefail
umask 077
aws s3 cp "s3://$BOWER_LAB_BUCKET/artifacts/manifest.json" /opt/bower-lab/manifest.json --only-show-errors
aws s3 cp "s3://$BOWER_LAB_BUCKET/artifacts/load.py" /opt/bower-lab/load.py --only-show-errors
python3 - <<'PY'
import hashlib,json
from pathlib import Path
p=Path('/opt/bower-lab')
assert hashlib.sha256((p/'load.py').read_bytes()).hexdigest()==json.loads((p/'manifest.json').read_text())['files']['load.py']
PY
python3 /opt/bower-lab/load.py --phase "${BOWER_LAB_PHASE:-correctness}" --count 100 --rate 50 --seconds 10 --deny-every 7 --seed-every 5
