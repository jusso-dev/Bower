#!/usr/bin/env python3
"""Fleet health check against the Bower management API (Python 3.9+ standard library only).

Reads GET /api/fleet (the console's fleet view: one plain state and traffic light per
collector, derived from heartbeats) and returns one verdict:

  exit 0 OK, 1 WARNING (any amber), 2 CRITICAL (any red), 3 UNKNOWN (API unreachable)

Authentication: a bearer token for the management API audience with the Viewer role, read
from the environment variable named by --token-env (for example set by
`az account get-access-token --resource api://<management-app-id> --query accessToken -o tsv`
in the same shell, never written to disk), or none for a development API on loopback.
Output: one-line summary, JSON or Prometheus text. Metadata only; never prints the token.
"""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request

OK, WARNING, CRITICAL, UNKNOWN = 0, 1, 2, 3
NAMES = {OK: "OK", WARNING: "WARNING", CRITICAL: "CRITICAL", UNKNOWN: "UNKNOWN"}
MAX_BODY = 8 * 1024 * 1024


def evaluate(fleet, ignore_states):
    """Returns (verdict, problems, metrics) for a /api/fleet document. Pure: no I/O."""
    problems = []
    metrics = {}
    verdict = OK
    for collector in fleet.get("collectors") or []:
        state, light = collector.get("state"), collector.get("light")
        key = f'bower_fleet_collector_light{{collector="{collector.get("id")}",state="{state}"}}'
        metrics[key] = {"green": 0, "amber": 1, "red": 2}.get(light, 0)
        if state in ignore_states or light not in ("amber", "red"):
            continue
        level = CRITICAL if light == "red" else WARNING
        verdict = max(verdict, level)
        problems.append({"level": NAMES[level], "collector": collector.get("id"), "state": state,
                         "label": collector.get("label"), "reason": collector.get("reason"),
                         "lastSeenAt": collector.get("lastSeenAt")})
    for item in fleet.get("states") or []:
        metrics[f'bower_fleet_collectors{{state="{item.get("state")}",light="{item.get("light")}"}}'] = item.get("collectors", 0)
    metrics["bower_fleet_check_status"] = verdict
    return verdict, problems, metrics


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--url", required=True, help="Management API base URL, for example https://bower.example.com")
    parser.add_argument("--token-env", help="Environment variable holding a bearer token (Viewer role)")
    parser.add_argument("--ignore-state", action="append", default=[],
                        help="Fleet state to ignore, for example old-version or waiting-for-approval (repeatable)")
    parser.add_argument("--timeout", type=float, default=10.0)
    parser.add_argument("--format", choices=("text", "json", "prometheus"), default="text")
    args = parser.parse_args(argv)
    request = urllib.request.Request(args.url.rstrip("/") + "/api/fleet", headers={"Accept": "application/json"})
    if args.token_env:
        token = os.environ.get(args.token_env, "").strip()
        if not token:
            print("UNKNOWN: token environment variable is empty")
            return UNKNOWN
        request.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(request, timeout=args.timeout) as response:  # noqa: S310 - operator URL
            body = response.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise ValueError("response-too-large")
        fleet = json.loads(body)
    except urllib.error.HTTPError as error:
        print(f"UNKNOWN: management API returned HTTP {error.code}")
        return UNKNOWN
    except (urllib.error.URLError, OSError, ValueError):
        print("UNKNOWN: management API unreachable or returned an invalid document")
        return UNKNOWN
    verdict, problems, metrics = evaluate(fleet, set(args.ignore_state))
    if args.format == "json":
        print(json.dumps({"status": NAMES[verdict], "generatedAt": fleet.get("generatedAt"), "problems": problems,
                          "metrics": metrics}, sort_keys=True))
    elif args.format == "prometheus":
        for name, value in sorted(metrics.items()):
            print(f"{name} {value}")
    else:
        detail = "; ".join(f"{item['collector']}: {item['label']} ({item['reason']})" for item in problems)
        print(f"{NAMES[verdict]}: {detail or 'every collector healthy'}")
    return verdict


if __name__ == "__main__":
    sys.exit(main())
