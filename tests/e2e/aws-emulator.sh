#!/usr/bin/env bash
# AWS signal path end to end against AWS Emulator (https://github.com/aws/aws-emulator).
# Needs the CI images bower-collector:ci and bower-cloud:ci, plus jq and gzip on the host.
# No AWS account or credentials: every AWS call goes to a local emulator (account
# 000000000000) that only containers sharing its network namespace can reach.
#
# The test deploys the real deploy/aws templates, checks the EventBridge rule patterns
# against the fixtures, then runs the cloud agent (SQS, S3 object reads) and a collector
# with the S3 output. It proves: EventBridge, Security Hub, CloudTrail and Firehose-object
# messages become exactly one S3 NDJSON line per event, redacted before the write and
# with SSE and a SHA-256 checksum; unsupported messages and buckets outside
# BOWER_AWS_S3_BUCKETS are dropped; malformed messages reach the dead-letter queue;
# redelivery is deduplicated; an S3 outage and a collector outage lose nothing; no secret
# or message body appears in any log.
#
# It does not prove AWS behaviour. EventBridge refuses PutEvents for aws.* sources (as
# AWS does), so fixtures are sent to SQS in the shape EventBridge delivers. See
# docs/operations/aws-emulator-testing.md for what this covers and what it does not.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
# mktemp -d is 0700: credentials, the token and test inputs stay private to this user.
# Containers get only $work/public (CA certificate, scopes, policies) mounted read-only.
work="$(mktemp -d)"
fixtures="$repo/tests/fixtures/aws-emulator"
prefix="bower-aws-e2e-$$"
emu="$prefix-emulator"
collector="$prefix-collector"
agent="$prefix-agent"
collector_image="${BOWER_COLLECTOR_IMAGE:-bower-collector:ci}"
cloud_image="${BOWER_CLOUD_IMAGE:-bower-cloud:ci}"
emulator_image="${BOWER_AWS_EMULATOR_IMAGE:-bower-aws-emulator:ci}"
cli_image=public.ecr.aws/aws-cli/aws-cli:2.34.32@sha256:4611a918d72fe666b94c4436386bc857a2c765cd5ffa07faaa651330cd5f30a7
curl_image=curlimages/curl:8.11.1@sha256:c1fe1679c34d9784c1b0d1e5f62ac0a79fca01fb6377cdd33e90473c6f9f9a69
region=ap-southeast-2
account=000000000000
emu_home=/home/emulator/.aws/emulator/9297
queue_url="https://sqs.$region.amazonaws.com/$account/bower-security"
dlq_url="https://sqs.$region.amazonaws.com/$account/bower-security-dlq"
output_bucket=bower-e2e-output
app_bucket=bower-e2e-app-logs
(umask 077 && touch "$work/secrets")
# Fixture content that must never reach a log, filtered from failure output as well.
printf '%s\n' never-forward-this 100000001 InstanceCredentialExfiltration >"$work/content"

cleanup() {
  status=$?
  if [ "$status" -ne 0 ]; then
    for name in "$collector" "$agent"; do
      echo "--- $name" >&2
      # Never print a secret or fixture content, even on failure.
      docker logs "$name" 2>&1 | grep -v -F -f "$work/secrets" -f "$work/content" >&2 || true
    done
  fi
  docker rm -f -v "$agent" "$collector" "$emu" >/dev/null 2>&1 || true
  rm -rf "$work"
  exit "$status"
}
trap cleanup EXIT
# A bare `test` that fails under set -e exits silently; name the failing check.
trap 'echo "FAIL: line $LINENO: $BASH_COMMAND" >&2' ERR

fail() {
  echo "FAIL: $*" >&2
  exit 1
}

# AWS CLI inside the emulator's network namespace, signed with this run's emulator keys.
aws_cli() {
  docker run --rm --network "container:$emu" --user "$(id -u):$(id -g)" --tmpfs /tmp -e HOME=/tmp \
    -v "$work/emu:$emu_home:ro" -v "$repo:/repo:ro" -v "$work/data:/data" \
    -e AWS_CONFIG_FILE="$emu_home/config" \
    -e AWS_SHARED_CREDENTIALS_FILE="$emu_home/emulator_credentials" \
    -e AWS_REGION="$region" -e AWS_DEFAULT_REGION="$region" \
    -e AWS_EC2_METADATA_DISABLED=true -e AWS_DISABLE_HOST_PREFIX_INJECTION=true \
    "$cli_image" "$@"
}

aws_json() {
  aws_cli "$@" --output json
}

status_queue() {
  # The header file is 0600; curl runs as its owner rather than the image user.
  docker run --rm --network "container:$emu" --user "$(id -u):$(id -g)" \
    -v "$work/status-header:/run/header:ro" "$curl_image" \
    -sf -H @/run/header http://127.0.0.1:4319/v1/status | jq -c .queue
}

queue_depth() {
  aws_json sqs get-queue-attributes --queue-url "$1" \
    --attribute-names ApproximateNumberOfMessages ApproximateNumberOfMessagesNotVisible \
    | jq -r '(.Attributes.ApproximateNumberOfMessages | tonumber) + (.Attributes.ApproximateNumberOfMessagesNotVisible | tonumber)'
}

delivered() {
  status_queue | jq -r .delivered
}

wait_until() {
  local description=$1 seconds=$2
  shift 2
  for _ in $(seq 1 "$seconds"); do
    if "$@"; then
      return 0
    fi
    sleep 1
  done
  fail "timed out after ${seconds}s waiting for $description"
}

delivered_is() { [ "$(delivered)" = "$1" ]; }
queue_is_empty() { [ "$(queue_depth "$queue_url")" = 0 ]; }
retrying() { [ "$(status_queue | jq -r .retrying)" -ge 1 ]; }
settled() { [ "$(status_queue | jq -r '.queued + .retrying + .uploading')" = 0 ]; }

send_fixture() {
  aws_cli sqs send-message --queue-url "$queue_url" --message-body "file://$1" --query MessageId --output text >/dev/null
}

# Downloads every output object; prints one compact JSON line per delivered event.
output_events() {
  rm -rf "$work/data/out"
  aws_cli s3 cp "s3://$output_bucket/" /data/out --recursive --only-show-errors
  find "$work/data/out" -type f -name '*.jsonl.gz' -exec gzip -dc {} + | jq -c .
}

# aws_cli runs as this user, so the owner-only data directory is enough for downloads.
(umask 077 && mkdir -p "$work/emu" "$work/data")
mkdir -p "$work/public/policies"
chmod 755 "$work/public" "$work/public/policies"

# 1. Emulator: loopback only, no published port, telemetry off, fresh keys and certificate.
docker run -d --name "$emu" --read-only --tmpfs /tmp --tmpfs /home/emulator:uid=1000 \
  --cap-drop ALL --security-opt no-new-privileges:true --memory 2g "$emulator_image" >/dev/null
emulator_ready() {
  docker exec "$emu" curl -sf --cacert "$emu_home/ca.pem" https://127.0.0.1:9297/__admin/health >/dev/null 2>&1
}
wait_until "the emulator health route" 60 emulator_ready
# docker cp cannot read a tmpfs, so copy the run's files out with exec.
for file in config emulator_credentials ca.pem; do
  docker exec "$emu" cat "$emu_home/$file" >"$work/emu/$file"
done
chmod 600 "$work/emu/config" "$work/emu/emulator_credentials"
chmod 644 "$work/emu/ca.pem"
sed -n 's/^aws_secret_access_key *= *//p' "$work/emu/emulator_credentials" >>"$work/secrets"

# Guard: these requests must reach the emulator, never AWS.
test "$(aws_json sts get-caller-identity | jq -r .Account)" = "$account" || fail "not talking to the emulator"

# Bower uses temporary credentials, as from an instance profile or IRSA: long-lived keys
# are refused by the agent.
aws_json sts get-session-token --duration-seconds 3600 >"$work/session.json"
jq -r '.Credentials | .SecretAccessKey, .SessionToken' "$work/session.json" >>"$work/secrets"
{
  jq -r '.Credentials | "AWS_ACCESS_KEY_ID=\(.AccessKeyId)\nAWS_SECRET_ACCESS_KEY=\(.SecretAccessKey)\nAWS_SESSION_TOKEN=\(.SessionToken)"' "$work/session.json"
  printf 'AWS_ENDPOINT_URL=https://127.0.0.1:9297\nSSL_CERT_FILE=/run/emu/ca.pem\n'
  printf 'AWS_EC2_METADATA_DISABLED=true\nAWS_REGION=%s\n' "$region"
} >"$work/aws.env"
rm -f "$work/session.json"
chmod 600 "$work/aws.env"

# 2. The shipped templates deploy, with the Australian region rule enforced.
aws_cli cloudformation deploy --stack-name bower-security \
  --template-file /repo/deploy/aws/bower-aws-security.yaml \
  --parameter-overrides RuleState=ENABLED MaxReceiveCount=3 --capabilities CAPABILITY_NAMED_IAM >/dev/null
aws_cli cloudformation deploy --stack-name bower-s3-output \
  --template-file /repo/deploy/aws/bower-s3-output.yaml \
  --parameter-overrides "BucketName=$output_bucket" --capabilities CAPABILITY_NAMED_IAM >/dev/null
outputs="$(aws_json cloudformation describe-stacks --stack-name bower-security --query 'Stacks[0].Outputs')"
test "$(jq -r '.[] | select(.OutputKey == "QueueUrl") | .OutputValue' <<<"$outputs")" = "$queue_url"
test "$(jq -r '.[] | select(.OutputKey == "DeadLetterQueueUrl") | .OutputValue' <<<"$outputs")" = "$dlq_url"
# shellcheck disable=SC2016 # JMESPath literal, not a shell expansion.
settings="$(aws_json cloudformation describe-stacks --stack-name bower-s3-output \
  --query 'Stacks[0].Outputs[?OutputKey==`CollectorSettings`].OutputValue | [0]' | jq -r .)"
test "$settings" = "BOWER_OUTPUT=s3 BOWER_S3_BUCKET=$output_bucket BOWER_S3_REGION=$region BOWER_S3_PREFIX=bower BOWER_S3_EXPECTED_BUCKET_OWNER=$account" \
  || fail "unexpected S3 output settings: $settings"

# 3. Each fixture matches exactly the deployed rules that should route it to the queue.
rules="$(aws_json events list-rules --name-prefix bower-security- | jq -c '[.Rules[] | {name: .Name, pattern: .EventPattern}]')"
test "$(jq length <<<"$rules")" = 6 || fail "expected six EventBridge rules"
matched_rules() {
  local event names=()
  event="$(jq -c . "$fixtures/$1")"
  while IFS=$'\t' read -r name pattern; do
    if [ "$(aws_cli events test-event-pattern --event-pattern "$pattern" --event "$event" --query Result --output text)" = True ]; then
      names+=("$(sed -E 's/^bower-security-(.*)-[A-Z0-9]+$/\1/' <<<"$name")")
    fi
  done < <(jq -r '.[] | [.name, .pattern] | @tsv' <<<"$rules")
  printf '%s\n' "${names[@]+"${names[@]}"}" | sort | paste -sd, -
}
expect_rules() {
  local actual
  actual="$(matched_rules "$1")"
  test "$actual" = "$2" || fail "$1 matched rules [$actual], expected [$2]"
}
expect_rules guardduty-finding.json GuardDutyRule
expect_rules root-console-login-failure.json ConsoleSignInRule,RootActivityRule
expect_rules cloudtrail-stop-logging.json CloudTrailControlRule
expect_rules unsupported-ec2-state-change.json ""
# Known emulator divergence (1.0.322): its pattern matcher never matches a field inside an
# array of objects, such as detail.findings[].Severity.Label. AWS flattens arrays, so the
# SecurityHubRule does match this event on AWS. Accept that gap, but still fail on any
# other result, and start asserting the AWS result once the emulator matches it.
securityhub_rules="$(matched_rules securityhub-findings-imported.json)"
case "$securityhub_rules" in
  SecurityHubRule) ;;
  "") echo "NOTE: AWS Emulator does not match patterns inside arrays of objects; SecurityHubRule not checked." ;;
  *) fail "securityhub-findings-imported.json matched rules [$securityhub_rules], expected [SecurityHubRule]" ;;
esac

# 4. A Firehose CloudWatch Logs object carrying one Bower envelope with a TFN.
aws_cli s3api create-bucket --bucket "$app_bucket" \
  --create-bucket-configuration "LocationConstraint=$region" >/dev/null
now="$(date -u +%Y-%m-%dT%H:%M:%S.000Z)"
envelope="$(jq -nc --arg now "$now" '{schemaVersion: "1.0.0", eventId: "aws-e2e-app-1", timeGenerated: $now,
  eventCategory: "authentication", eventType: "authentication_failure", eventAction: "authentication.attempt",
  eventResult: "failure", eventOutcomeReason: "InvalidPassword for TFN 100000001",
  application: {name: "AwsE2E", environment: "e2e"}, actor: {username: "aws-e2e"}, source: {ipAddress: "192.0.2.10"}}')"
jq -nc --arg message "$envelope" '{messageType: "DATA_MESSAGE", owner: "000000000000", logGroup: "/aws/lambda/app",
  logStream: "stream", subscriptionFilters: ["bower"], logEvents: [{id: "1", timestamp: 1, message: $message}]}' \
  | gzip -c >"$work/data/app.gz"
aws_cli s3api put-object --bucket "$app_bucket" --key bower/app/1.gz --body /data/app.gz >/dev/null
s3_notification() {
  jq -nc --arg bucket "$1" --arg key "$2" --argjson size "$(wc -c <"$work/data/app.gz")" '{Records: [{
    eventVersion: "2.1", eventSource: "aws:s3", awsRegion: "ap-southeast-2", eventName: "ObjectCreated:Put",
    s3: {bucket: {name: $bucket, arn: ("arn:aws:s3:::" + $bucket)}, object: {key: $key, size: $size}}}]}'
}
s3_notification "$app_bucket" bower/app/1.gz >"$work/data/app-notification.json"
s3_notification not-an-allowed-bucket bower/app/1.gz >"$work/data/denied-notification.json"
printf 'not json' >"$work/data/malformed.txt"

# 5. Collector (S3 output) and cloud agent share the emulator's loopback.
token="$(head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
printf '%s\n' "$token" >>"$work/secrets"
# The Docker CLI reads the 0600 env-file on the host; no token file is mounted.
printf 'BOWER_INGEST_TOKEN=%s\n' "$token" >>"$work/aws.env"
(umask 077 && printf 'Authorization: Bearer %s\n' "$token" >"$work/status-header")
cp "$work/emu/ca.pem" "$work/public/ca.pem"
cp "$repo"/policies/default/*.yaml "$repo"/packs/aws-security/policies/*.yaml "$work/public/policies/"
# Exact producer identity tuples for the events above; anything else is refused.
jq -n '[
  {producer: "default", application: {name: "aws-security", environment: "e2e", tenantId: "123456789012"}},
  {producer: "default", application: {name: "aws-security", environment: "e2e", tenantId: "123456789012"}, source: {ipAddress: "203.0.113.10"}},
  {producer: "default", application: {name: "aws-security", environment: "e2e", tenantId: "123456789012"}, source: {ipAddress: "198.51.100.7"}},
  {producer: "default", application: {name: "AwsE2E", environment: "e2e"}, source: {ipAddress: "192.0.2.10"}}]' >"$work/public/producer-scopes.json"
chmod 644 "$work/public/ca.pem" "$work/public/producer-scopes.json" "$work/public/policies"/*

docker run -d --name "$collector" --network "container:$emu" --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --env-file "$work/aws.env" -v "$work/public:/run/emu:ro" \
  -e BOWER_LISTEN_URL=http://127.0.0.1:4319 -e BOWER_COLLECTOR_ID=aws-e2e -e BOWER_ENVIRONMENT=e2e \
  -e BOWER_PRODUCER_SCOPES_FILE=/run/emu/producer-scopes.json \
  -e BOWER_POLICY_DIRECTORY=/run/emu/policies -e BOWER_OUTPUT=s3 -e BOWER_S3_BUCKET="$output_bucket" \
  -e BOWER_S3_REGION="$region" -e BOWER_S3_EXPECTED_BUCKET_OWNER="$account" -e BOWER_S3_SSE=AES256 \
  "$collector_image" >/dev/null
collector_ready() { status_queue >/dev/null 2>&1; }
wait_until "the collector" 30 collector_ready

docker run -d --name "$agent" --network "container:$emu" --read-only --tmpfs /tmp \
  --cap-drop ALL --security-opt no-new-privileges:true \
  --env-file "$work/aws.env" -v "$work/public:/run/emu:ro" \
  -e BOWER_AWS_SQS_QUEUE_URL="$queue_url" -e BOWER_AWS_S3_BUCKETS="$app_bucket" \
  -e BOWER_COLLECTOR_URL=http://127.0.0.1:4319 \
  -e BOWER_ENVIRONMENT=e2e -e BOWER_REQUIRE_AU_REGION=true -e BOWER_RETRY_SECONDS=10 \
  -e BOWER_CLOUD_HEARTBEAT_DIR=/tmp "$cloud_image" >/dev/null

# 6. Forward: 5 EventBridge events (Security Hub carries two findings) plus 1 from S3.
# The TFN finding adds the privacy engine's own sensitive_data_detected event: 7 in all.
for fixture in guardduty-finding root-console-login-failure cloudtrail-stop-logging securityhub-findings-imported \
  unsupported-ec2-state-change; do
  send_fixture "/repo/tests/fixtures/aws-emulator/$fixture.json"
done
send_fixture /data/app-notification.json
send_fixture /data/denied-notification.json
send_fixture /data/malformed.txt
wait_until "seven delivered events" 60 delivered_is 7
wait_until "the source queue to drain" 60 queue_is_empty
test "$(queue_depth "$dlq_url")" = 1 || fail "only the malformed message belongs in the dead-letter queue"

events="$(output_events)"
test "$(wc -l <<<"$events" | tr -d ' ')" = 7 || fail "expected seven output lines"
test -z "$(jq -r .eventId <<<"$events" | sort | uniq -d)" || fail "duplicate event ids in S3"
test "$(jq -r .eventType <<<"$events" | sort | paste -sd, -)" \
  = "authentication_failure,aws_cloudtrail,aws_cloudtrail,aws_guardduty,aws_security_hub,aws_security_hub,sensitive_data_detected"
test "$(jq -r 'select(.eventId == "aws-e2e-app-1") | .eventOutcomeReason' <<<"$events")" = "InvalidPassword for TFN *****0001"
test "$(jq -c 'select(.eventId == "aws-e2e-app-1") | .privacy.detected' <<<"$events")" = '["au.tfn"]'
test "$(jq -r 'select(.eventType == "sensitive_data_detected") | .target.id' <<<"$events")" = aws-e2e-app-1
if grep -q -e never-forward-this -e 100000001 <<<"$events"; then
  fail "an unredacted value reached S3"
fi
test "$(jq -r .collector.id <<<"$events" | sort -u)" = aws-e2e

# Every object: under the collector's prefix, SSE-S3, SHA-256 checksum, gzip NDJSON.
objects="$(aws_cli s3api list-objects-v2 --bucket "$output_bucket" --query 'Contents[].Key' --output text | tr '\t' '\n')"
for key in $objects; do
  [[ "$key" == bower/aws-e2e/* && "$key" == *.jsonl.gz ]] || fail "unexpected object key layout"
  head="$(aws_json s3api head-object --bucket "$output_bucket" --key "$key" --checksum-mode ENABLED)"
  test "$(jq -r '[.ServerSideEncryption, (.ChecksumSHA256 != null), .ContentEncoding] | @tsv' <<<"$head")" \
    = "$(printf 'AES256\ttrue\tgzip')" || fail "object missing encryption, checksum or gzip"
done

# 7. Redelivery is deduplicated: the same GuardDuty finding adds nothing.
object_count="$(wc -w <<<"$objects" | tr -d ' ')"
send_fixture /repo/tests/fixtures/aws-emulator/guardduty-finding.json
wait_until "the redelivered message to settle" 60 queue_is_empty
sleep 3
test "$(delivered)" = 7 || fail "a redelivered message was delivered twice"
test "$(aws_cli s3api list-objects-v2 --bucket "$output_bucket" --query 'length(Contents)' --output text)" = "$object_count"

# 8. S3 outage: an explicit bucket-policy deny holds events in the durable queue as
# retryable; restoring the policy delivers them exactly once.
policy="$(aws_cli s3api get-bucket-policy --bucket "$output_bucket" --query Policy --output text)"
jq -c --arg bucket "$output_bucket" '.Statement += [{Sid: "E2eOutage", Effect: "Deny", Principal: "*",
  Action: "s3:PutObject", Resource: ("arn:aws:s3:::" + $bucket + "/*")}]' <<<"$policy" >"$work/data/outage-policy.json"
printf '%s' "$policy" >"$work/data/policy.json"
aws_cli s3api put-bucket-policy --bucket "$output_bucket" --policy file:///data/outage-policy.json
jq -c '.detail.eventID = "4e1d2b9a-0000-4000-8000-0000000000e1"' "$fixtures/cloudtrail-stop-logging.json" >"$work/data/outage-1.json"
send_fixture /data/outage-1.json
wait_until "an S3 access-denied retry" 60 retrying
docker logs "$collector" 2>&1 | grep -q 'destination-s3-access-denied' || fail "S3 deny was not classified"
test "$(status_queue | jq -r .deadLettered)" = 0
aws_cli s3api put-bucket-policy --bucket "$output_bucket" --policy file:///data/policy.json
wait_until "delivery after the S3 outage" 120 delivered_is 8
wait_until "the collector queue to settle" 30 settled

# 9. Collector outage: the agent probes before receiving, so the message is not received
# (no delivery attempt is spent) until the collector is back.
docker stop "$collector" >/dev/null
jq -c '.detail.id = "aws-e2e-outage-2"' "$fixtures/guardduty-finding.json" >"$work/data/outage-2.json"
send_fixture /data/outage-2.json
sleep 25
attributes="$(aws_json sqs get-queue-attributes --queue-url "$queue_url" \
  --attribute-names ApproximateNumberOfMessages ApproximateNumberOfMessagesNotVisible)"
test "$(jq -r '.Attributes | "\(.ApproximateNumberOfMessages)/\(.ApproximateNumberOfMessagesNotVisible)"' <<<"$attributes")" = 1/0 \
  || fail "the agent received while the collector was down"
docker start "$collector" >/dev/null
wait_until "delivery after the collector outage" 90 delivered_is 9
wait_until "the source queue to drain" 30 queue_is_empty
test "$(output_events | jq -r .eventId | sort | uniq -d)" = "" || fail "duplicate event ids after outages"
test "$(output_events | wc -l | tr -d ' ')" = 9

# 10. Logs carry ids, counts and failure codes only: no secrets, no message bodies.
# A blank pattern would match every line and hide a real leak behind a false failure.
! grep -qx '' "$work/secrets" || fail "empty secret pattern"
# Capture each whole log first: grep -q exiting early under pipefail could hide a match.
for name in "$collector" "$agent"; do
  docker logs "$name" >"$work/log" 2>&1
  if grep -q -F -f "$work/secrets" "$work/log"; then
    fail "a secret appeared in the $name log"
  fi
  if grep -q -F -f "$work/content" "$work/log"; then
    fail "message content appeared in the $name log"
  fi
done
rm -f "$work/log"

echo "AWS emulator e2e passed: templates deployed, rules matched, 9 events delivered to S3 exactly once and redacted, outages recovered."
