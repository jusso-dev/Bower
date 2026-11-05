#!/bin/bash
# Runs a command with homelab-admin credentials exported into its environment only
# (the AWS default chain's environment provider). Nothing is written to disk or printed.
set -euo pipefail
eval "$(aws configure export-credentials --profile homelab-admin --format env)"
export AWS_REGION=ap-southeast-2 AWS_DEFAULT_REGION=ap-southeast-2
unset AWS_PROFILE
exec "$@"
