#!/bin/bash
# Uploads drill artifacts to the run's private bucket (after verifying the account).
set -euo pipefail
state=$1; source_dir=$2
bucket=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1]))["outputs"]["Bucket"])' "$state")
test "$(aws --profile homelab-admin sts get-caller-identity --query Account --output text)" = 959038055523
aws --profile homelab-admin --region ap-southeast-2 s3 sync --only-show-errors --sse AES256 "$source_dir/" "s3://$bucket/artifacts/"
