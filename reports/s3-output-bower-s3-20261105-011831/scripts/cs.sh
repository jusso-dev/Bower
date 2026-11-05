#!/bin/bash
export DOTNET_ROOT=$HOME/.dotnet RUST_LOG=info
export BOWER_LISTEN_URL=http://127.0.0.1:4391 BOWER_QUEUE_PATH=<rundir>/cs-queue/bower.db
export BOWER_POLICY_DIRECTORY=<repo>/policies/default BOWER_COLLECTOR_ID=bower-s3-20261105-011831-csharp BOWER_ENVIRONMENT=lab
export BOWER_INGEST_TOKEN=$(cat <rundir>/token) BOWER_SINGLE_TRUST_DOMAIN=true
export BOWER_OUTPUT=s3 BOWER_S3_BUCKET=bower-s3-20261105-011831-lab BOWER_S3_REGION=ap-southeast-2 BOWER_S3_PREFIX=bower
export BOWER_S3_EXPECTED_BUCKET_OWNER=<account>
# Lab host disk is 97% full: lower free-space watermarks for this run only.
export BOWER_STORAGE_CRITICAL_FREE_BYTES=1073741824 BOWER_STORAGE_CRITICAL_FREE_PERCENT=1 BOWER_STORAGE_WARNING_FREE_BYTES=2147483648 BOWER_STORAGE_WARNING_FREE_PERCENT=2
exec $HOME/.dotnet/dotnet <repo>/src/Bower.Collector/bin/Release/net10.0/Bower.Collector.dll
