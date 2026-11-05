#!/bin/bash
export DOTNET_ROOT=$HOME/.dotnet
export BOWER_LISTEN_URL=http://127.0.0.1:4391 BOWER_QUEUE_PATH=<rundir>/cs-queue/bower.db
export BOWER_POLICY_DIRECTORY=<repo>/policies/default BOWER_COLLECTOR_ID=bower-s3-20261105-004926-csharp BOWER_ENVIRONMENT=lab
export BOWER_INGEST_TOKEN=$(cat <rundir>/token) BOWER_SINGLE_TRUST_DOMAIN=true
export BOWER_OUTPUT=s3 BOWER_S3_BUCKET=bower-s3-20261105-004926-lab BOWER_S3_REGION=ap-southeast-2 BOWER_S3_PREFIX=csharp
export BOWER_S3_EXPECTED_BUCKET_OWNER=<account>
exec $HOME/.dotnet/dotnet <repo>/src/Bower.Collector/bin/Release/net10.0/Bower.Collector.dll
