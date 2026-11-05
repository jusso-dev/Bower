#!/bin/bash
# Runs a command with the lab collector role's temporary credentials only (assumed with the
# homelab-admin user), exported into the process environment: the default chain's
# environment provider. Nothing is written to disk or printed.
set -euo pipefail
ROLE_ARN="$1"; shift
eval "$(aws configure export-credentials --profile homelab-admin --format env)"
unset AWS_PROFILE
CREDS=$(aws sts assume-role --role-arn "$ROLE_ARN" --role-session-name "${BOWER_LAB_RUN:-bower-lab}" --duration-seconds 3600 --query 'Credentials.[AccessKeyId,SecretAccessKey,SessionToken]' --output text)
read -r AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN <<<"$CREDS"
export AWS_ACCESS_KEY_ID AWS_SECRET_ACCESS_KEY AWS_SESSION_TOKEN AWS_REGION=ap-southeast-2 AWS_DEFAULT_REGION=ap-southeast-2
exec "$@"
