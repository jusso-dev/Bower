"""Reconciles downloaded S3 objects against the event ids that were sent: every id must
appear exactly once, keys must match the Bower layout (hash of ordered ids, UTC hour of the
first event's receive time is not checked here: receive time is not in the payload)."""
import argparse, collections, gzip, hashlib, json, pathlib, re

parser = argparse.ArgumentParser()
parser.add_argument("--objects", required=True)
parser.add_argument("--expected", nargs="+", required=True, help="prefix=file.json or prefix=@id1,id2")
parser.add_argument("--out", required=True)
args = parser.parse_args()
root = pathlib.Path(args.objects)
seen = collections.Counter()
objects = []
key_pattern = re.compile(r"^(?P<prefix>.+)/(\d{4})/(\d{2})/(\d{2})/(\d{2})/(?P<hash>[0-9a-f]{64})\.jsonl(\.gz)?$")
for path in sorted(p for p in root.rglob("*") if p.is_file()):
    key = path.relative_to(root).as_posix()
    data = path.read_bytes()
    body = gzip.decompress(data) if key.endswith(".gz") else data
    lines = body.decode().splitlines()
    ids = [json.loads(line)["eventId"] for line in lines]
    match = key_pattern.match(key)
    key_ok = bool(match) and match["hash"] == hashlib.sha256("\n".join(ids).encode()).hexdigest()
    for event_id in ids:
        seen[(match["prefix"] if match else "?", event_id)] += 1
    objects.append({"key": key, "events": len(ids), "bytes": len(data), "keyMatchesLayout": key_ok,
                    "gzip": key.endswith(".gz")})
results = {}
all_expected = set()
for spec in args.expected:
    prefix, source = spec.split("=", 1)
    if source.startswith("@"):
        expected = source[1:].split(",")
    else:
        expected = [item["eventId"] for item in json.load(open(source))["events"] if item["queued"]]
    all_expected.update((prefix, event_id) for event_id in expected)
    counts = [seen[(prefix, event_id)] for event_id in expected]
    results[prefix] = {"expected": len(expected), "exactlyOnce": sum(1 for c in counts if c == 1),
                       "missing": [e for e, c in zip(expected, counts) if c == 0],
                       "duplicated": [e for e, c in zip(expected, counts) if c > 1]}
unexpected = sorted(f"{p}:{e}" for (p, e) in seen if (p, e) not in all_expected)
summary = {"objects": objects, "objectCount": len(objects), "prefixes": results, "unexpected": unexpected,
           "allKeysMatchLayout": all(o["keyMatchesLayout"] for o in objects),
           "pass": all(not r["missing"] and not r["duplicated"] for r in results.values())
                   and not unexpected and all(o["keyMatchesLayout"] for o in objects)}
json.dump(summary, open(args.out, "w"), indent=2)
print(json.dumps({k: summary[k] for k in ("objectCount", "allKeysMatchLayout", "pass")} | {"prefixes": {p: {k: v for k, v in r.items() if k in ("expected", "exactlyOnce")} for p, r in results.items()}, "unexpected": len(unexpected)}))
