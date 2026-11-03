#!/usr/bin/env python3
"""Reconcile a replay test with Log Analytics and Microsoft Sentinel.

Uses the signed-in Azure CLI identity (a Log Analytics and Sentinel reader) through
`az rest`; never prints or stores tokens. Output is metadata-only JSON: exact counts,
times, addresses and detection keys, never RawEnvelope payloads.

  query   --workspace-id <customer id> --kql <query>        run one query
  report  --workspace-id <id> --workspace-resource <arm id> --manifest <file>
          [--expect <file>]                                  full reconciliation
"""

import argparse
import collections
import datetime
import json
import re
import subprocess
import sys

API = "https://api.loganalytics.io"
SENTINEL_API = "2025-09-01"


def az_rest(method, url, body=None, resource=None):
    command = ["az", "rest", "--method", method, "--url", url, "-o", "json"]
    if resource:
        command += ["--resource", resource]
    if body is not None:
        command += ["--body", json.dumps(body), "--headers", "Content-Type=application/json"]
    result = subprocess.run(command, check=True, capture_output=True, text=True)
    return json.loads(result.stdout) if result.stdout.strip() else {}


def query(workspace, kql, timespan="P3D"):
    data = az_rest("post", f"{API}/v1/workspaces/{workspace}/query", {"query": kql, "timespan": timespan}, API)
    if "error" in data:
        raise SystemExit(json.dumps(data["error"]))
    table = data["tables"][0]
    names = [column["name"] for column in table["columns"]]
    return [dict(zip(names, row)) for row in table["rows"]]


def alert_entities(workspace, alert_ids):
    # Fallback when the incident entities API fails: the incident's alerts carry the same
    # mapped entities in SecurityAlert.Entities.
    ids = ", ".join(json.dumps(alert_id) for alert_id in alert_ids)
    rows = query(workspace, f"""SecurityAlert
| where SystemAlertId in ({ids})
| mv-expand Entity = todynamic(Entities)
| project Kind = tolower(tostring(Entity.Type)), Address = tostring(Entity.Address), HostName = tostring(Entity.HostName)""")
    kinds = {"ip": "Ip", "host": "Host"}
    return [{"kind": kinds.get(row["Kind"], row["Kind"]),
             "properties": {"address": row["Address"] or None, "hostName": row["HostName"] or None}} for row in rows]


def incidents(resource, workspace):
    url = f"https://management.azure.com{resource}/providers/Microsoft.SecurityInsights/incidents?api-version={SENTINEL_API}"
    items = []
    while url:
        page = az_rest("get", url)
        items += page.get("value", [])
        url = page.get("nextLink")
    found = []
    for item in items:
        alerts = az_rest("post", f"https://management.azure.com{item['id']}/alerts?api-version={SENTINEL_API}").get("value", [])
        alert_ids = sorted(alert["properties"].get("systemAlertId") for alert in alerts)
        source = "incident-entities-api"
        try:
            entities = az_rest("post", f"https://management.azure.com{item['id']}/entities?api-version={SENTINEL_API}").get("entities", [])
        except subprocess.CalledProcessError:
            # Seen live: HTTP 500 on every call for incidents managed by Microsoft Defender XDR.
            entities, source = alert_entities(workspace, alert_ids), "SecurityAlert.Entities"
        properties = item["properties"]
        found.append({
            "incidentNumber": properties.get("incidentNumber"), "title": properties.get("title"),
            "createdTimeUtc": properties.get("createdTimeUtc"), "status": properties.get("status"),
            "alertCount": properties.get("additionalData", {}).get("alertsCount"),
            "alertIds": alert_ids, "entitySource": source,
            "ipAddresses": sorted({entity["properties"].get("address") for entity in entities
                                   if entity.get("kind") == "Ip"} - {None}),
            "hosts": sorted({entity["properties"].get("hostName") for entity in entities
                             if entity.get("kind") == "Host"} - {None}),
        })
    return sorted(found, key=lambda value: value["incidentNumber"])


ROWS = """BowerSecurity_CL
| where EventId startswith "ws2-"
| project EventId, CollectorId, EventType, SourceIpAddress, TimeGenerated, Ingested = ingestion_time(),
    SentTime = tostring(RawEnvelope.timeGenerated)"""

ALERTS = """SecurityAlert
| where ProviderName == "ASI Scheduled Alerts"
| extend Details = todynamic(tostring(todynamic(ExtendedProperties)["Custom Details"]))
| extend Key = tostring(Details.BowerDetectionKey[0]), Path = tostring(Details.EvaluationPath[0]),
    Crossed = tostring(Details.CrossedAt[0]), Evaluated = tostring(Details.EvaluatedAt[0]),
    Replayed = tostring(Details.ReplayedRows[0]), Late = tostring(Details.LateEvents[0]),
    Distinct = tostring(Details.DistinctEvents[0])
| summarize arg_min(TimeGenerated, *) by SystemAlertId
| project SystemAlertId, AlertName, TimeGenerated, StartTime, EndTime, Key, Path, Crossed, Evaluated, Replayed, Late,
    Distinct, Entities"""


# The deployed function, checked against the raw rows: exact counts, never dcount().
PARSER = """let raw = BowerSecurity_CL | where EventId startswith "ws2";
let parsed = BowerSecurityEvents | where EventId startswith "ws2";
print RawRows = toscalar(raw | count),
    RawIdentities = toscalar(raw | summarize by CollectorId, EventId | count),
    RawEventIds = toscalar(raw | summarize by EventId | count),
    ParserEvents = toscalar(parsed | count), ParserCopies = toscalar(parsed | summarize sum(BowerCopies)),
    ParserCollectors = toscalar(parsed | summarize make_set(CollectorId)),
    HealthRowsRaw = toscalar(BowerSecurity_CL | where EventType == "collector_health" | count),
    HealthRowsInParser = toscalar(BowerSecurityEvents | where EventType == "collector_health" | count)"""


def report(args):
    manifest = [json.loads(line) for line in open(args.manifest, encoding="utf-8")]
    expected = collections.defaultdict(set)
    for item in manifest:
        expected[item["scenario"]].add(item["eventId"])
    rows = query(args.workspace_id, ROWS)
    by_id = collections.defaultdict(list)
    for row in rows:
        by_id[row["EventId"]].append(row)
    scenarios = {}
    for scenario, ids in sorted(expected.items()):
        present = [event_id for event_id in ids if event_id in by_id]
        copies = collections.Counter(len(by_id[event_id]) for event_id in present)
        # Compare parsed times: Log Analytics trims trailing zeros, so the strings differ in length.
        delays = [(min(_time(r["Ingested"]) for r in by_id[e]) - _time(by_id[e][0]["SentTime"] or by_id[e][0]["TimeGenerated"])).total_seconds()
                  for e in present]
        replay_gaps = [(max(_time(r["Ingested"]) for r in by_id[e]) - min(_time(r["Ingested"]) for r in by_id[e])).total_seconds()
                       for e in present if len(by_id[e]) > 1]
        scenarios[scenario] = {
            "expectedDistinct": len(ids), "presentDistinct": len(present), "missing": len(ids) - len(present),
            "rows": sum(len(by_id[e]) for e in present), "extraRows": sum(len(by_id[e]) - 1 for e in present),
            "copiesHistogram": {str(k): v for k, v in sorted(copies.items())},
            "firstIngestionDelaySeconds": {"min": min(delays, default=None), "max": max(delays, default=None)},
            "replayGapSeconds": {"min": min(replay_gaps, default=None), "max": max(replay_gaps, default=None)},
            "addresses": sorted({item["address"] for item in manifest if item["scenario"] == scenario}),
            "methods": sorted({item["method"] for item in manifest if item["scenario"] == scenario}),
        }
    unexpected = sorted(set(by_id) - {e for ids in expected.values() for e in ids})
    parser = query(args.workspace_id, PARSER)[0]
    alerts = query(args.workspace_id, ALERTS)
    keys = collections.Counter(alert["Key"] for alert in alerts if alert["Key"])
    found_incidents = incidents(args.workspace_resource, args.workspace_id)
    per_address = collections.defaultdict(int)
    per_host = collections.defaultdict(int)
    for incident in found_incidents:
        for address in incident["ipAddresses"]:
            per_address[address] += 1
        for host in incident["hosts"]:
            per_host[host] += 1
    result = {
        "generatedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        "scenarios": scenarios, "unexpectedEventIds": len(unexpected), "parser": parser,
        "alerts": alerts, "alertsPerDetectionKey": dict(sorted(keys.items())),
        "duplicateAlertKeys": sorted(key for key, count in keys.items() if count > 1),
        "incidents": found_incidents, "incidentsPerAddress": dict(sorted(per_address.items())),
        "incidentsPerHost": dict(sorted(per_host.items())),
    }
    if args.expect:
        expect = json.load(open(args.expect, encoding="utf-8"))
        checks = {}
        for address, count in expect.get("incidentsPerAddress", {}).items():
            checks[f"incidents:{address}"] = per_address.get(address, 0) == count
        for host, count in expect.get("incidentsPerHost", {}).items():
            checks[f"incidents:host:{host}"] = per_host.get(host, 0) == count
        # Each fault must really have happened, or the scenario proves nothing.
        for scenario, count in expect.get("minExtraRows", {}).items():
            checks[f"replayed:{scenario}"] = scenarios.get(scenario, {}).get("extraRows", 0) >= count
        for scenario, seconds in expect.get("minReplayGapSeconds", {}).items():
            gap = scenarios.get(scenario, {}).get("replayGapSeconds", {}).get("min")
            checks[f"replayGap:{scenario}"] = gap is not None and gap >= seconds
        for scenario, seconds in expect.get("minFirstIngestionDelaySeconds", {}).items():
            delay = scenarios.get(scenario, {}).get("firstIngestionDelaySeconds", {}).get("min")
            checks[f"delayed:{scenario}"] = delay is not None and delay >= seconds
        for key_prefix, count in expect.get("alertsPerKeyPrefix", {}).items():
            checks[f"alerts:{key_prefix}"] = sum(v for k, v in keys.items() if k.startswith(key_prefix)) == count
        checks["noMissingEvents"] = all(s["missing"] == 0 for s in scenarios.values())
        # One parser row per (CollectorId, EventId), every raw row accounted for as a copy.
        checks["parserCollapsesEveryReplay"] = (parser["ParserEvents"] == parser["RawIdentities"]
                                                and parser["ParserCopies"] == parser["RawRows"])
        if expect.get("singleIdentityPerEventId"):
            checks["identityEqualsEventId"] = parser["RawIdentities"] == parser["RawEventIds"]
        checks["parserExcludesHealthRecords"] = parser["HealthRowsRaw"] > 0 and parser["HealthRowsInParser"] == 0
        checks["noDuplicateAlertKeys"] = not result["duplicateAlertKeys"]
        checks["noUnexpectedEvents"] = not unexpected
        result["checks"] = checks
        result["passed"] = all(checks.values())
    print(json.dumps(result, indent=1, sort_keys=True))
    # A failed expectation must fail the command, not only say so in the report.
    return 1 if args.expect and not result["passed"] else 0


def _time(value):
    # Log Analytics returns up to 100 ns precision with trailing zeros trimmed; Python 3.9's
    # fromisoformat accepts exactly three or six fractional digits.
    value = re.sub(r"\.(\d+)", lambda m: "." + (m.group(1) + "000000")[:6], value.replace("Z", "+00:00"))
    return datetime.datetime.fromisoformat(value)


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    sub = parser.add_subparsers(dest="command", required=True)
    one = sub.add_parser("query")
    one.add_argument("--workspace-id", required=True)
    one.add_argument("--kql", required=True)
    one.add_argument("--timespan", default="P3D")
    full = sub.add_parser("report")
    full.add_argument("--workspace-id", required=True)
    full.add_argument("--workspace-resource", required=True)
    full.add_argument("--manifest", required=True)
    full.add_argument("--expect")
    args = parser.parse_args(argv)
    if args.command == "query":
        print(json.dumps(query(args.workspace_id, args.kql, args.timespan), indent=1))
    else:
        return report(args)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
