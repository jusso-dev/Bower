#!/bin/bash
# Old (installed dev.264) and new (PR dev.277) collector binaries against simulated future queues.
set -uo pipefail
B='{{Artifacts}}'; R='{{REGION}}'
w=/var/lib/bower/future-test; rm -rf $w; install -d -o bower -g bower -m 0700 $w
aws s3 cp "s3://$B/artifacts/pr-linux-x64.tar.gz" /opt/bower-lab/pr-linux-x64.tar.gz --region "$R" --only-show-errors
rm -rf /opt/bower-lab/pr && mkdir -p /opt/bower-lab/pr && tar -C /opt/bower-lab/pr -xzf /opt/bower-lab/pr-linux-x64.tar.gz 2>/dev/null
/opt/bower-lab/pr/cli/bower queue backup --database /var/lib/bower/queue.db --output $w/base.db >/dev/null
install -d -o bower -g bower -m 0700 $w/bin && cp /opt/bower-lab/pr/collector/Bower.Collector /opt/bower-lab/pr/collector/libe_sqlite3.so $w/bin/ && chown -R bower:bower $w/bin
results='[]'
for variant in A B; do
  for bin in old new; do
    d=$w/$variant-$bin; install -d -o bower -g bower -m 0700 $d; cp $w/base.db $d/queue.db; chown bower:bower $d/queue.db
    sql="INSERT INTO schema_history(version, applied_at, hash) VALUES (6, '2027-01-01T00:00:00Z', 'future');"
    [ $variant = B ] && sql="DROP VIEW queue_events; ALTER TABLE queue_events_v5 RENAME TO queue_events_v6; $sql"
    sqlite3 $d/queue.db "PRAGMA journal_mode=WAL; $sql PRAGMA wal_checkpoint(TRUNCATE);" >/dev/null
    before=$(sha256sum $d/queue.db | cut -c1-64); objects_before=$(sqlite3 "file:$d/queue.db?mode=ro" 'select count(*) from sqlite_master')
    exe=/opt/bower/Bower.Collector; [ $bin = new ] && exe=$w/bin/Bower.Collector
    out=$(sudo -u bower env -i BOWER_QUEUE_PATH=$d/queue.db BOWER_LISTEN_URL=http://127.0.0.1:4339 BOWER_POLICY_DIRECTORY=/etc/bower/no-defaults \
          BOWER_OUTPUT=none BOWER_INGEST_TOKEN_FILE=/etc/bower/secrets/token BOWER_COLLECTOR_ID=future-test timeout 20 $exe 2>&1 | grep -m1 -E 'Bower collector failed|Now listening' ); rc=$?
    sqlite3 $d/queue.db 'PRAGMA wal_checkpoint(TRUNCATE);' >/dev/null 2>&1
    after=$(sha256sum $d/queue.db | cut -c1-64); objects_after=$(sqlite3 "file:$d/queue.db?mode=ro" 'select count(*) from sqlite_master')
    tables=$(sqlite3 "file:$d/queue.db?mode=ro" "select group_concat(name) from (select name from sqlite_master where type in ('table','view') and name like 'queue_events%' order by name)")
    results=$(python3 -c "import json,sys;r=json.loads(sys.argv[1]);r.append({'variant':sys.argv[2],'binary':sys.argv[3],'error':sys.argv[4][:300],'unchanged':sys.argv[5]==sys.argv[6],'objectsBefore':int(sys.argv[7]),'objectsAfter':int(sys.argv[8]),'queueTablesAfter':sys.argv[9]});print(json.dumps(r))" "$results" $variant $bin "$out" $before $after $objects_before $objects_after "$tables")
  done
done
echo "$results" | python3 -m json.tool | tee /var/lib/bower-lab/snap/z01-future-schema.json
sha256sum /opt/bower/Bower.Collector $w/bin/Bower.Collector
rm -rf $w
aws s3 cp /var/lib/bower-lab/snap/z01-future-schema.json "s3://$B/results/$(hostname -s)/z01-future-schema.json" --region "$R" --only-show-errors
