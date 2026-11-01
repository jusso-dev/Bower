#!/bin/bash
# Upload only to this drill run's tagged bucket in the expected account.
set -euo pipefail
state=$1; source_dir=$2
run_id=$(python3 -c 'import json,re,sys; value=json.load(open(sys.argv[1]))["runId"]; re.fullmatch(r"bower-(ws6|fw)-[0-9]{8}-[0-9]{6}", value) or sys.exit("Invalid run ID"); print(value)' "$state")
bucket=$(python3 -c 'import json,re,sys; value=json.load(open(sys.argv[1]))["outputs"]["Bucket"]; re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", value) or sys.exit("Invalid bucket"); print(value)' "$state")
test "$(aws --profile homelab-admin --region ap-southeast-2 sts get-caller-identity --query Account --output text)" = 959038055523
aws --profile homelab-admin --region ap-southeast-2 s3api get-bucket-tagging --bucket "$bucket" --output json |
  python3 -c 'import json,sys; tags={x["Key"]: x["Value"] for x in json.load(sys.stdin)["TagSet"]}; (tags.get("Project") == "bower-lab" and tags.get("RunId") == sys.argv[1]) or sys.exit("Bucket ownership tags do not match")' "$run_id"
aws --profile homelab-admin --region ap-southeast-2 s3 sync --only-show-errors --sse AES256 "$source_dir/" "s3://$bucket/artifacts/"
