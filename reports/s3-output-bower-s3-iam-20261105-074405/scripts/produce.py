"""Posts a known set of synthetic authentication_failure events to a collector's
/v1/events and records the event ids sent and the HTTP statuses (no token, no payloads)."""
import argparse, json, os, urllib.request
from datetime import datetime, timezone

parser = argparse.ArgumentParser()
parser.add_argument("--url", required=True)
parser.add_argument("--run", required=True)
parser.add_argument("--runtime", required=True)
parser.add_argument("--count", type=int, required=True)
parser.add_argument("--out", required=True)
args = parser.parse_args()
token = os.environ["BOWER_LAB_INGEST_TOKEN"]
sent = []
for index in range(args.count):
    identity = f"{args.run}-{args.runtime}-{index:04d}"
    body = {"schemaVersion": "1.0.0", "eventId": identity, "eventOriginalId": identity,
            "timeGenerated": datetime.now(timezone.utc).isoformat(), "eventCategory": "authentication",
            "eventType": "authentication_failure", "eventAction": "authentication.attempt",
            "eventResult": "failure", "eventOutcomeReason": "synthetic s3 output qualification",
            "application": {"name": "BowerS3Lab", "environment": "lab"},
            "actor": {"username": "synthetic-lab-operator"}, "source": {"ipAddress": "192.0.2.10"},
            "request": {"correlationId": identity}}
    request = urllib.request.Request(args.url.rstrip("/") + "/v1/events", data=json.dumps(body).encode(),
                                     headers={"Content-Type": "application/json", "Authorization": f"Bearer {token}"})
    with urllib.request.urlopen(request, timeout=10) as response:
        result = json.loads(response.read())
        sent.append({"eventId": identity, "status": response.status, "decision": result.get("decision"),
                     "queued": result.get("queued")})
json.dump({"runtime": args.runtime, "count": len(sent), "events": sent}, open(args.out, "w"), indent=2)
print(json.dumps({"runtime": args.runtime, "sent": len(sent),
                  "accepted": sum(1 for item in sent if item["status"] in (200, 202) and item["queued"])}))
