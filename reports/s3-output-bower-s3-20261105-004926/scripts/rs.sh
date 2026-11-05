#!/bin/bash
export BOWER_LISTEN_URL=http://127.0.0.1:4392 BOWER_QUEUE_PATH=<rundir>/rs-queue/bower.db
export BOWER_POLICY_DIRECTORY=<repo>/policies/default BOWER_COLLECTOR_ID=bower-s3-20261105-004926-rust BOWER_ENVIRONMENT=lab
export BOWER_INGEST_TOKEN=$(cat <rundir>/token) BOWER_SINGLE_TRUST_DOMAIN=true
export BOWER_OUTPUT=s3 BOWER_S3_BUCKET=bower-s3-20261105-004926-lab BOWER_S3_REGION=ap-southeast-2 BOWER_S3_PREFIX=rust
export BOWER_S3_EXPECTED_BUCKET_OWNER=<account> RUST_LOG=info
exec <repo>/rust/target/debug/bower-collector
