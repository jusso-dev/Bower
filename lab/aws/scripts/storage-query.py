#!/usr/bin/env python3
"""Independently query storage-pressure lab identities in Log Analytics.

Uses the separate verifier identity in an isolated Azure CLI cache that must already
hold only that service principal. The access token stays in memory; the report holds
counts, digests and timings only. Sequence numbers are synthetic (ws3lNNNNNNN for the
syslog sender, ws3wNNNNNNN for Windows); Windows usernames are HMAC pseudonyms and are
mapped back to sequence numbers with a host-produced mapping that is never committed.
"""
import argparse
import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import urllib.request
from pathlib import Path

MAXIMUM_RESPONSE_BYTES = 128 * 1024 * 1024


def token(config_dir, client_id):
    environment = {**os.environ, "AZURE_CONFIG_DIR": str(config_dir)}
    account = json.loads(subprocess.run(["az", "account", "show", "-o", "json"], env=environment,
                                        check=True, capture_output=True, text=True).stdout)
    if account["user"]["type"] != "servicePrincipal" or account["user"]["name"] != client_id:
        raise SystemExit("Refusing: the isolated cache is not the verifier service principal")
    result = subprocess.run(["az", "account", "get-access-token", "--resource", "https://api.loganalytics.io",
                             "--query", "accessToken", "-o", "tsv"], env=environment, check=True,
                            capture_output=True, text=True)
    return result.stdout.strip()


def query(workspace, access_token, text):
    request = urllib.request.Request(f"https://api.loganalytics.io/v1/workspaces/{workspace}/query",
        data=json.dumps({"query": text}).encode(), method="POST",
        headers={"Authorization": "Bearer " + access_token, "Content-Type": "application/json"})
    with urllib.request.urlopen(request, timeout=300) as response:
        body = response.read(MAXIMUM_RESPONSE_BYTES + 1)
    if len(body) > MAXIMUM_RESPONSE_BYTES:
        raise SystemExit("Response too large")
    data = json.loads(body)
    if data.get("error") or "tables" not in data:
        raise SystemExit("Partial or failed query results cannot establish delivery")
    table = data["tables"][0]
    names = [column["name"] for column in table["columns"]]
    return [dict(zip(names, row)) for row in table["rows"]]


def parse(value):
    text = re.sub(r"\.(\d+)(?=[Z+-])", lambda match: "." + (match.group(1) + "000000")[:6], value)
    return dt.datetime.fromisoformat(text.replace("Z", "+00:00"))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--azure-config-dir", type=Path, required=True)
    parser.add_argument("--workspace-id", required=True)
    parser.add_argument("--verifier-client-id", required=True)
    parser.add_argument("--collector", choices=["ws3-linux", "ws3-wec"], required=True)
    parser.add_argument("--since", required=True)
    parser.add_argument("--expected", type=int, required=True, help="Sequence numbers 1..N were generated")
    parser.add_argument("--mapping", type=Path, help="Windows: JSON {hmac-hex: ws3wNNNNNNN}")
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if Path.home() / ".azure" == args.azure_config_dir.resolve():
        raise SystemExit("Refusing the operator's default Azure CLI cache")
    since = dt.datetime.fromisoformat(args.since.replace("Z", "+00:00"))
    windows = args.collector == "ws3-wec"
    kind = "authentication_failure" if windows else "network_connection_denied"
    rows = query(args.workspace_id, token(args.azure_config_dir, args.verifier_client_id), f"""
BowerSecurity_CL
| where TimeGenerated >= datetime({since.strftime('%Y-%m-%dT%H:%M:%SZ')}) and CollectorId == '{args.collector}'
| project EventId, EventType, CorrelationId, ActorUsername, TimeGenerated, Ingested=ingestion_time()""")
    mapping = json.loads(args.mapping.read_text()) if args.mapping else {}
    prefix = "ws3w" if windows else "ws3l"
    expected = {f"{prefix}{seq:07d}" for seq in range(1, args.expected + 1)}
    events = [row for row in rows if row["EventType"] == kind]
    def sequence(row):
        if windows:
            return mapping.get((row["ActorUsername"] or "").split(":")[-1])
        return row["CorrelationId"]
    by_sequence = {}
    for row in events:
        value = sequence(row)
        if value:
            by_sequence.setdefault(value, set()).add(row["EventId"])
    event_ids = [row["EventId"] for row in events]
    digest = lambda values: hashlib.sha256("\n".join(sorted(values)).encode()).hexdigest()
    latencies = sorted((parse(row["Ingested"]) - parse(row["TimeGenerated"])).total_seconds() for row in events)
    quantile = lambda q: latencies[max(0, int(len(latencies) * q + 0.999999) - 1)] if latencies else None
    report = {
        "phase": "destination-query", "queriedAt": dt.datetime.now(dt.timezone.utc).isoformat(), "queryRole": "verifier",
        "collector": args.collector, "since": since.isoformat(), "rows": len(rows),
        "rowsByEventType": {name: sum(1 for row in rows if row["EventType"] == name) for name in sorted({row["EventType"] for row in rows})},
        "eventRows": len(events), "distinctEventIds": len(set(event_ids)), "duplicateRows": len(event_ids) - len(set(event_ids)),
        "expectedSequences": len(expected), "distinctSequences": len(by_sequence),
        "missingSequences": len(expected - set(by_sequence)), "missingSample": sorted(expected - set(by_sequence))[:20],
        "unexpectedSequences": len(set(by_sequence) - expected),
        "sequencesWithSeveralEventIds": sum(1 for ids in by_sequence.values() if len(ids) > 1),
        "expectedDigest": digest(expected), "destinationDigest": digest(by_sequence),
        "ingestionLatencySeconds": {"p50": quantile(.5), "p95": quantile(.95), "p99": quantile(.99),
                                    "maximum": latencies[-1] if latencies else None},
    }
    args.output.write_text(json.dumps(report, indent=1) + "\n")
    print(json.dumps({key: report[key] for key in ("rows", "eventRows", "duplicateRows", "distinctSequences", "missingSequences", "unexpectedSequences")}))


if __name__ == "__main__":
    main()
