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
import urllib.parse
import re

OK, WARNING, CRITICAL, UNKNOWN = 0, 1, 2, 3
NAMES = {OK: "OK", WARNING: "WARNING", CRITICAL: "CRITICAL", UNKNOWN: "UNKNOWN"}
MAX_BODY = 8 * 1024 * 1024


def safe_base_url(value):
    """Reject cleartext remote requests and ambiguous authorities before reading a token."""
    try:
        if any(ord(char) <= 32 or ord(char) == 127 for char in value) or "\\" in value:
            return False
        parts = urllib.parse.urlsplit(value)
        if not parts.hostname or parts.username is not None or parts.password is not None or parts.query or parts.fragment:
            return False
        _ = parts.port  # Reject malformed or out-of-range ports.
        if parts.scheme == "https":
            return True
        return parts.scheme == "http" and bool(re.fullmatch(r"(?:127\.0\.0\.1|\[::1\])(?::[0-9]+)?", parts.netloc, re.IGNORECASE))
    except ValueError:
        return False


class NoRedirect(urllib.request.HTTPRedirectHandler):
    """Never forward a monitoring request or its bearer token to a redirect target."""
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def prometheus_label(value):
    text = str(value)
    text = "".join(char if ord(char) >= 32 and ord(char) != 127 or char == "\n" else "?" for char in text)
    return text.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def text_value(value):
    # JSON escaping keeps one-line text safe from terminal control sequences.
    return json.dumps(str(value), ensure_ascii=True)[1:-1]


def evaluate(fleet, ignore_states):
    """Returns (verdict, problems, metrics) for a /api/fleet document. Pure: no I/O."""
    if not isinstance(fleet, dict) or not isinstance(fleet.get("collectors"), list):
        raise ValueError("invalid-fleet")
    if not isinstance(fleet.get("states", []), list):
        raise ValueError("invalid-fleet-states")
    if not fleet["collectors"]:
        return UNKNOWN, [{"level": "UNKNOWN", "collector": "fleet", "state": "empty",
                          "label": "No collectors", "reason": "Check the fleet configuration.",
                          "lastSeenAt": None}], {"bower_fleet_check_status": UNKNOWN}
    problems = []
    metrics = {}
    verdict = OK
    active_collectors = 0
    for collector in fleet["collectors"]:
        if not isinstance(collector, dict) or not isinstance(collector.get("id"), str):
            raise ValueError("invalid-collector")
        state, light = collector.get("state"), collector.get("light")
        if state != "removed":
            active_collectors += 1
        key = f'bower_fleet_collector_light{{collector="{prometheus_label(collector.get("id"))}",state="{prometheus_label(state)}"}}'
        metrics[key] = {"green": 0, "none": 0, "amber": 1, "red": 2}.get(light, 3)
        if state in ignore_states or light == "green" or (state == "removed" and light == "none"):
            continue
        level = CRITICAL if light == "red" else WARNING if light == "amber" else UNKNOWN
        rank = {OK: 0, WARNING: 1, UNKNOWN: 2, CRITICAL: 3}
        if rank[level] > rank[verdict]:
            verdict = level
        problems.append({"level": NAMES[level], "collector": collector.get("id"), "state": state,
                         "label": collector.get("label"), "reason": collector.get("reason"),
                         "lastSeenAt": collector.get("lastSeenAt")})
    if active_collectors == 0:
        if verdict != CRITICAL:
            verdict = UNKNOWN
        problems.append({"level": "UNKNOWN", "collector": "fleet", "state": "empty",
                         "label": "No active collectors", "reason": "Check fleet configuration.",
                         "lastSeenAt": None})
    for item in fleet.get("states") or []:
        if not isinstance(item, dict):
            raise ValueError("invalid-fleet-state")
        if not isinstance(item.get("collectors"), int) or isinstance(item.get("collectors"), bool) or item["collectors"] < 0:
            raise ValueError("invalid-fleet-count")
        metrics[f'bower_fleet_collectors{{state="{prometheus_label(item.get("state"))}",light="{prometheus_label(item.get("light"))}"}}'] = item.get("collectors", 0)
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
    if not safe_base_url(args.url):
        print("UNKNOWN: monitoring URL must use HTTPS or literal loopback HTTP")
        return UNKNOWN
    request = urllib.request.Request(args.url.rstrip("/") + "/api/fleet", headers={"Accept": "application/json"})
    if args.token_env:
        token = os.environ.get(args.token_env, "").strip()
        if not token:
            print("UNKNOWN: token environment variable is empty")
            return UNKNOWN
        request.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.build_opener(NoRedirect()).open(request, timeout=args.timeout) as response:
            body = response.read(MAX_BODY + 1)
        if len(body) > MAX_BODY:
            raise ValueError("response-too-large")
        fleet = json.loads(body)
    except urllib.error.HTTPError as error:
        print(f"UNKNOWN: management API returned HTTP {error.code}")
        return UNKNOWN
    except (urllib.error.URLError, OSError, ValueError, RecursionError):
        print("UNKNOWN: management API unreachable or returned an invalid document")
        return UNKNOWN
    try:
        verdict, problems, metrics = evaluate(fleet, set(args.ignore_state))
    except (TypeError, ValueError, RecursionError):
        print("UNKNOWN: management API returned an invalid fleet document")
        return UNKNOWN
    if args.format == "json":
        print(json.dumps({"status": NAMES[verdict], "generatedAt": fleet.get("generatedAt"), "problems": problems,
                          "metrics": metrics}, sort_keys=True))
    elif args.format == "prometheus":
        for name, value in sorted(metrics.items()):
            print(f"{name} {value}")
    else:
        detail = "; ".join(f"{text_value(item['collector'])}: {text_value(item['label'])} ({text_value(item['reason'])})" for item in problems)
        print(f"{NAMES[verdict]}: {detail or 'every collector healthy'}")
    return verdict


if __name__ == "__main__":
    sys.exit(main())
