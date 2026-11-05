"""Reconciles downloaded S3 objects against the event ids that were sent, per key namespace
(<prefix>/<collectorId>): every expected id must appear exactly the expected number of times,
and every key must equal the Bower layout (object hash over length-prefixed ids plus the
SHA-256 of the uncompressed body)."""
import argparse, collections, gzip, hashlib, json, pathlib, re, struct

parser = argparse.ArgumentParser()
parser.add_argument("--objects", required=True)
parser.add_argument("--expected", nargs="+", required=True,
                    help="namespace=sent1.json,sent2.json or namespace=@id1,id2[#times]")
parser.add_argument("--out", required=True)
args = parser.parse_args()


def object_hash(ids, body):
    digest = hashlib.sha256(struct.pack(">I", len(ids)))
    for event_id in ids:
        raw = event_id.encode()
        digest.update(struct.pack(">I", len(raw)) + raw)
    digest.update(hashlib.sha256(body).digest())
    return digest.hexdigest()


root = pathlib.Path(args.objects)
pattern = re.compile(r"^(?P<ns>.+)/\d{4}/\d{2}/\d{2}/\d{2}/(?P<hash>[0-9a-f]{64})\.jsonl(\.gz)?$")
seen = collections.Counter()
objects = []
for path in sorted(p for p in root.rglob("*") if p.is_file()):
    key = path.relative_to(root).as_posix()
    data = path.read_bytes()
    body = gzip.decompress(data) if key.endswith(".gz") else data
    ids = [json.loads(line)["eventId"] for line in body.decode().splitlines()]
    match = pattern.match(key)
    namespace = match["ns"] if match else "?"
    for event_id in ids:
        seen[(namespace, event_id)] += 1
    objects.append({"key": key, "namespace": namespace, "events": len(ids), "bytes": len(data),
                    "bodySha256": hashlib.sha256(body).hexdigest(),
                    "keyMatchesLayout": bool(match) and match["hash"] == object_hash(ids, body)})
results, expected_all = {}, set()
for spec in args.expected:
    namespace, source = spec.split("=", 1)
    times = 1
    if source.startswith("@"):
        source, _, count = source[1:].partition("#")
        expected, times = source.split(","), int(count or 1)
    else:
        expected = [item["eventId"] for name in source.split(",")
                    for item in json.load(open(name))["events"] if item["queued"]]
    expected_all.update((namespace, event_id) for event_id in expected)
    counts = [seen[(namespace, event_id)] for event_id in expected]
    results[namespace] = {"expected": len(expected), "timesEach": times,
                          "matched": sum(1 for c in counts if c == times),
                          "missing": [e for e, c in zip(expected, counts) if c == 0],
                          "wrongCount": [e for e, c in zip(expected, counts) if c not in (0, times)]}
unexpected = sorted(f"{n}:{e}" for (n, e) in seen if (n, e) not in expected_all)
summary = {"objects": objects, "objectCount": len(objects), "namespaces": results, "unexpected": unexpected,
           "allKeysMatchLayout": all(o["keyMatchesLayout"] for o in objects)}
summary["pass"] = summary["allKeysMatchLayout"] and not unexpected and all(
    r["matched"] == r["expected"] for r in results.values())
json.dump(summary, open(args.out, "w"), indent=2)
print(json.dumps({"objectCount": len(objects), "allKeysMatchLayout": summary["allKeysMatchLayout"],
                  "pass": summary["pass"], "unexpected": len(unexpected),
                  "namespaces": {n: f'{r["matched"]}/{r["expected"]} x{r["timesEach"]}' for n, r in results.items()}}))
