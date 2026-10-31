#!/bin/bash
set -euo pipefail
aws s3 cp "s3://{{Artifacts}}/artifacts/{{FILE}}" "/opt/bower-lab/{{FILE}}" --region "{{REGION}}" --only-show-errors
sha256sum "/opt/bower-lab/{{FILE}}"
