#!/usr/bin/env python3
"""Records Azure Monitor alert state for the monitoring drill (metadata only).

`watch` polls the Alerts Management API for one rule (and optional dimension values) until
an alert instance that started at or after --since reaches the wanted monitor condition,
then prints the instance and the seconds from --since. `list` prints every instance in the
resource group. Uses the operator's Azure CLI login through `az rest` (argument arrays, no
shell); never prints tokens.
"""

import argparse
import json
import re
import subprocess
import sys
import time
from datetime import datetime, timezone

API = "2019-05-05-preview"


def parse_time(value):
    """Parses ISO 8601 with any fractional precision (.NET writes seven digits)."""
    if not value:
        return None
    match = re.fullmatch(r"(.+?)(?:\.(\d+))?(Z|[+-]\d{2}:\d{2})?", value)
    if match is None:
        raise ValueError("invalid-time")
    head, fraction, offset = match.groups()
    text = head + ("." + fraction[:6].ljust(6, "0") if fraction else "") + ("+00:00" if offset in (None, "Z") else offset)
    return datetime.fromisoformat(text)


def instances(subscription, group):
    url = (f"https://management.azure.com/subscriptions/{subscription}/providers/Microsoft.AlertsManagement/alerts"
           f"?api-version={API}&targetResourceGroup={group}&timeRange=1d&includeContext=true")
    result = []
    while url:
        completed = subprocess.run(["az", "rest", "--method", "get", "--url", url, "-o", "json"],
                                   capture_output=True, text=True, check=True, timeout=120)
        page = json.loads(completed.stdout)
        for item in page.get("value", []):
            result.append(normalise(item))
        url = page.get("nextLink")
    return result


def normalise(item):
    essentials = item["properties"]["essentials"]
    context = (item["properties"].get("context") or {}).get("context") or {}
    dimensions = {}
    for condition in (context.get("condition") or {}).get("allOf") or []:
        for dimension in condition.get("dimensions") or []:
            dimensions[dimension.get("name")] = dimension.get("value")
    return {
        "id": item["id"].rsplit("/", 1)[-1],
        "rule": essentials.get("alertRule", "").rsplit("/", 1)[-1],
        "severity": essentials.get("severity"),
        "monitorCondition": essentials.get("monitorCondition"),
        "startDateTime": essentials.get("startDateTime"),
        "resolvedDateTime": essentials.get("monitorConditionResolvedDateTime"),
        "dimensions": dimensions,
    }


def incidents(subscription, group, workspace):
    url = (f"https://management.azure.com/subscriptions/{subscription}/resourceGroups/{group}/providers/"
           f"Microsoft.OperationalInsights/workspaces/{workspace}/providers/Microsoft.SecurityInsights/incidents"
           "?api-version=2024-03-01")
    completed = subprocess.run(["az", "rest", "--method", "get", "--url", url, "-o", "json"],
                               capture_output=True, text=True, check=True, timeout=120)
    return [{"title": item["properties"].get("title"), "severity": item["properties"].get("severity"),
             "status": item["properties"].get("status"), "createdTimeUtc": item["properties"].get("createdTimeUtc"),
             "firstActivityTimeUtc": item["properties"].get("firstActivityTimeUtc"),
             "lastActivityTimeUtc": item["properties"].get("lastActivityTimeUtc"),
             "alerts": (item["properties"].get("additionalData") or {}).get("alertsCount")}
            for item in json.loads(completed.stdout).get("value", [])]


def matches(instance, rule, dimensions, since):
    if instance["rule"].lower() != rule.lower():
        return False
    if any(instance["dimensions"].get(key) != value for key, value in dimensions.items()):
        return False
    started = parse_time(instance["startDateTime"])
    return started is not None and started >= since


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("list", "watch", "incidents"))
    parser.add_argument("--workspace", help="Workspace name, for incidents")
    parser.add_argument("--subscription", required=True)
    parser.add_argument("--resource-group", required=True)
    parser.add_argument("--rule")
    parser.add_argument("--dimension", action="append", default=[], help="NAME=VALUE")
    parser.add_argument("--since", help="UTC ISO time of the fault (watch Fired) or recovery (watch Resolved)")
    parser.add_argument("--condition", choices=("Fired", "Resolved"), default="Fired")
    parser.add_argument("--timeout", type=int, default=3600)
    parser.add_argument("--interval", type=int, default=30)
    args = parser.parse_args(argv)
    if args.command == "incidents":
        print(json.dumps(incidents(args.subscription, args.resource_group, args.workspace), indent=1, sort_keys=True))
        return 0
    if args.command == "list":
        print(json.dumps(instances(args.subscription, args.resource_group), indent=1, sort_keys=True))
        return 0
    dimensions = dict(item.split("=", 1) for item in args.dimension)
    since = parse_time(args.since)
    deadline = time.monotonic() + args.timeout
    while time.monotonic() < deadline:
        for instance in instances(args.subscription, args.resource_group):
            if not matches(instance, args.rule, dimensions, since if args.condition == "Fired" else datetime.min.replace(tzinfo=timezone.utc)):
                continue
            if instance["monitorCondition"] != args.condition:
                continue
            at = parse_time(instance["startDateTime"] if args.condition == "Fired" else instance["resolvedDateTime"])
            if at is None or at < since:
                continue
            instance["secondsFromSince"] = round((at - since).total_seconds(), 1)
            instance["since"] = args.since
            print(json.dumps(instance, sort_keys=True))
            return 0
        time.sleep(args.interval)
    print(json.dumps({"rule": args.rule, "dimensions": dimensions, "since": args.since,
                      "condition": args.condition, "result": "timeout"}), file=sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
