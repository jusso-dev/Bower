#!/bin/bash
# Soak firewall source on the owned sender: a transient systemd unit runs real nftables denials
# through the reviewed syslog-host.py generator, segment by segment at absolute start times.
# Identities are sequence numbers (a13-n<port>x<sport>) from FIRST upwards, so every event is
# accounted for exactly. 10/sec steady and, unless BOWER_SOAK_SMOKE=1, a 60-second 100/sec
# burst at +2 h, +6 h, ... Each segment's generator record (sent, nftables counter delta,
# actual rate) is uploaded to results/sender/soak/<run>/<label>/. Public parameters only:
#   BOWER_SOAK_ACTION=start|status, BOWER_SOAK_LABEL, BOWER_SOAK_START (epoch),
#   BOWER_SOAK_SECONDS, BOWER_SOAK_FIRST, BOWER_SOAK_SMOKE.
set -euo pipefail
umask 077
: "${BOWER_LAB_BUCKET:?}" "${BOWER_LAB_RUN:?}" "${BOWER_SOAK_LABEL:?}"
[[ "$BOWER_LAB_RUN" =~ ^bower-soak-[0-9]{8}-[0-9]{6}$ && "$BOWER_SOAK_LABEL" =~ ^[a-z0-9-]{1,40}$ ]]
[ "$(id -u)" = 0 ]
dir=/var/lib/bower-lab/soak/$BOWER_SOAK_LABEL
if [ "${BOWER_SOAK_ACTION:-status}" = status ]; then
  systemctl show "bower-soak-gen-$BOWER_SOAK_LABEL" --property=ActiveState,Result,ExecMainStatus --no-pager || true
  ls "$dir" 2>/dev/null | tail -3
  tail -c 600 "$dir/segments.jsonl" 2>/dev/null || true
  exit 0
fi
: "${BOWER_SOAK_START:?}" "${BOWER_SOAK_SECONDS:?}" "${BOWER_SOAK_FIRST:?}"
# Non-negative integers only: a negative FIRST maps to ports outside the Track A rule.
[[ "$BOWER_SOAK_START" =~ ^[0-9]+$ && "$BOWER_SOAK_SECONDS" =~ ^[0-9]+$ && "$BOWER_SOAK_FIRST" =~ ^[0-9]+$ ]] ||
  { echo '{"error":"start, seconds and first must be non-negative integers"}'; exit 1; }
[ ! -e "$dir" ] || { echo '{"error":"label already used"}'; exit 1; }
mkdir -p "$dir"
sed -n '/^# WORKER$/,/^WORKER$/p' "$0" | sed '1d;$d' > "$dir/worker.py"
systemd-run --quiet --unit="bower-soak-gen-$BOWER_SOAK_LABEL" --property=Type=exec \
  --setenv=BOWER_LAB_BUCKET="$BOWER_LAB_BUCKET" --setenv=BOWER_LAB_RUN="$BOWER_LAB_RUN" --setenv=BOWER_LAB_HOST=SenderR \
  --setenv=AWS_DEFAULT_REGION=ap-southeast-2 \
  /usr/bin/python3 "$dir/worker.py" "$dir" "$BOWER_SOAK_LABEL" "$BOWER_SOAK_START" "$BOWER_SOAK_SECONDS" "$BOWER_SOAK_FIRST" "${BOWER_SOAK_SMOKE:-0}"
echo "{\"started\":\"bower-soak-gen-$BOWER_SOAK_LABEL\",\"workerSha256\":\"$(sha256sum "$dir/worker.py" | cut -c1-64)\"}"
exit 0
# The worker below is data for bash (a quoted here-document), extracted by the sed above.
: <<'WORKER'
# WORKER
import json
import os
from pathlib import Path
import subprocess
import sys
import time

directory, label, start, seconds, first, smoke = Path(sys.argv[1]), sys.argv[2], int(sys.argv[3]), int(sys.argv[4]), int(sys.argv[5]), sys.argv[6] == '1'
bursts = [] if smoke else list(range(7200, seconds - 59, 14400))
edges = sorted({0, seconds, *bursts, *(b + 60 for b in bursts)})
segments = []
for begin, end in zip(edges, edges[1:]):
    rate = 100 if begin in bursts else 10
    for at in range(begin, end, 7200):
        segments.append((at, min(7200, end - at), rate))
# The Track A nftables rule logs ports 4400..4449, 40,000 identities each: indices 0..1,999,999.
if not 0 <= first or first + sum(n * r for _, n, r in segments) > 2000000:
    raise SystemExit('identity range outside the Track A rule (0..1,999,999)')
(directory / 'plan.json').write_text(json.dumps({'label': label, 'start': start, 'seconds': seconds, 'first': first,
                                                 'segments': segments, 'total': sum(s * r for _, s, r in segments)}))
index = first
for number, (offset, length, rate) in enumerate(segments, 1):
    name = '%s-%03d' % (label, number)
    count = length * rate
    planned = start + offset
    # Never refuse a late segment (that would lose its identities); record the actual start.
    at = max(planned, time.time() + 1)
    result = subprocess.run(['python3', '/opt/bower-lab/syslog-host.py', 'generate', '--kind', 'nft', '--track', 'A',
                             '--first', str(index), '--count', str(count), '--rate', str(rate), '--at', str(at),
                             '--label', name], capture_output=True, text=True)
    record = {'segment': number, 'label': name, 'first': index, 'count': count, 'rate': rate, 'plannedStart': planned,
              'requestedStart': at, 'exitCode': result.returncode}
    try:
        record['generator'] = json.loads(Path('/var/lib/bower-lab/results/generate-' + name + '.json').read_text())
    except (OSError, ValueError):
        record['generator'] = None
    with (directory / 'segments.jsonl').open('a') as stream:
        stream.write(json.dumps(record) + '\n')
    index += count
    subprocess.run(['aws', 's3', 'cp', '--only-show-errors', '--sse', 'AES256', str(directory / 'segments.jsonl'),
                    's3://%s/results/sender/soak/%s/%s/segments.jsonl' % (os.environ['BOWER_LAB_BUCKET'], os.environ['BOWER_LAB_RUN'], label)],
                   timeout=120)
(directory / 'done.json').write_text(json.dumps({'label': label, 'last': index - 1, 'finishedAt': time.time()}))
subprocess.run(['aws', 's3', 'cp', '--only-show-errors', '--sse', 'AES256', str(directory / 'done.json'),
                's3://%s/results/sender/soak/%s/%s/done.json' % (os.environ['BOWER_LAB_BUCKET'], os.environ['BOWER_LAB_RUN'], label)], timeout=120)
WORKER
