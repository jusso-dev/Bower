#!/usr/bin/env python3
"""Send synthetic replay-test events to a Bower collector or the Logs Ingestion API.

collector  POST pack-shaped semantic events to a test collector's /v1/events, so the
           collector's policy, durable queue and Azure output deliver them.
direct     upload Bower-shaped rows straight to the DCR stream with an explicit
           event time, for exact timing control (late, replayed or rewritten rows).
           Uses the signed-in Azure CLI identity for the token; never prints it.

Every event uses documentation addresses (RFC 5737) and synthetic names. The
manifest records event IDs, addresses and times only; keep it out of source control.
"""

import argparse
import datetime
import json
import subprocess
import sys
import urllib.request
import uuid

KINDS = {
    "logon": {
        "eventCategory": "authentication", "eventType": "authentication_failure",
        "eventAction": "authentication.attempt", "eventResult": "failure",
        "eventOutcomeReason": "InvalidCredentials",
        "application": {"name": "windows-security", "environment": "validation"},
    },
    "deny": {
        "eventCategory": "network-security", "eventType": "network_connection_denied",
        "eventAction": "network.connect", "eventResult": "denied",
        "eventOutcomeReason": "FirewallPolicyDeny",
        "application": {"name": "nftables-firewall", "environment": "validation"},
    },
}


def now():
    return datetime.datetime.now(datetime.timezone.utc)


def stamp(value):
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def event(kind, scenario, address, index, at):
    body = {"schemaVersion": "1.0.0", "eventId": f"ws2-{scenario}-{kind}-{index:04d}-{uuid.uuid4().hex[:12]}",
            "timeGenerated": stamp(at), **KINDS[kind], "source": {"ipAddress": address},
            "labels": {"replayTest": scenario}}
    if kind == "logon":
        body["actor"] = {"username": f"lab-user-{index % 7}"}
    return body


def post(url, body, headers=None):
    request = urllib.request.Request(url, json.dumps(body).encode(), method="POST",
                                     headers={"Content-Type": "application/json", **(headers or {})})
    with urllib.request.urlopen(request, timeout=30) as response:
        return response.status


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("mode", choices=["collector", "direct"])
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--kind", choices=sorted(KINDS), required=True)
    parser.add_argument("--address", required=True)
    parser.add_argument("--count", type=int, required=True)
    parser.add_argument("--age-minutes", type=float, default=0, help="event time this far in the past")
    parser.add_argument("--collector", default="http://127.0.0.1:4319")
    parser.add_argument("--endpoint", help="DCE logs ingestion endpoint (direct)")
    parser.add_argument("--dcr", help="DCR immutable ID (direct)")
    parser.add_argument("--collector-id", default="replay-direct", help="collector.id stamped on direct rows")
    parser.add_argument("--replay-of", help="manifest whose rows are uploaded again unchanged (direct)")
    parser.add_argument("--manifest", required=True)
    args = parser.parse_args(argv)

    start = now()
    if args.replay_of:
        rows = [json.loads(line)["row"] for line in open(args.replay_of, encoding="utf-8")]
    else:
        at = start - datetime.timedelta(minutes=args.age_minutes)
        rows = [event(args.kind, args.scenario, args.address, index, at + datetime.timedelta(milliseconds=index))
                for index in range(args.count)]
    with open(args.manifest, "a", encoding="utf-8") as manifest:
        if args.mode == "collector":
            for row in rows:
                status = post(args.collector.rstrip("/") + "/v1/events", row)
                if status not in (200, 202):
                    raise SystemExit(f"collector returned {status} for {row['eventId']}")
                manifest.write(json.dumps({"scenario": args.scenario, "method": "collector", "eventId": row["eventId"],
                                           "address": args.address, "eventTime": row["timeGenerated"],
                                           "sentAt": stamp(now())}) + "\n")
        else:
            token = subprocess.run(["az", "account", "get-access-token", "--resource", "https://monitor.azure.com",
                                    "--query", "accessToken", "-o", "tsv"], check=True, capture_output=True,
                                   text=True).stdout.strip()
            for row in rows:
                row.setdefault("collector", {"id": args.collector_id, "version": "replay-test",
                                             "sourceAdapter": "direct-logs-ingestion"})
            url = f"{args.endpoint.rstrip('/')}/dataCollectionRules/{args.dcr}/streams/Custom-BowerSecurity?api-version=2023-01-01"
            status = post(url, rows, {"Authorization": "Bearer " + token})
            del token
            sent = stamp(now())
            for row in rows:
                manifest.write(json.dumps({"scenario": args.scenario, "method": "direct", "eventId": row["eventId"],
                                           "address": args.address, "eventTime": row["timeGenerated"],
                                           "sentAt": sent, "httpStatus": status, "row": row}) + "\n")
    print(json.dumps({"scenario": args.scenario, "mode": args.mode, "events": len(rows), "startedAt": stamp(start),
                      "finishedAt": stamp(now())}))


if __name__ == "__main__":
    main(sys.argv[1:])
