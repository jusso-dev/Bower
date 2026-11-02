#!/usr/bin/env python3
"""Strict Azure cleanup audit for a replay-safe detection test run.

Absence counts only when an independent query proves it: an empty listing, `false` from
`az group exists`, or the exact not-found code for a direct lookup. Any other error is
recorded as not absent. Metadata only. Usage:

  cleanup_audit.py --state azure-state.json --subscription ID --output cleanup.json

State: {"runId", "group", "workspaceName", "identities": {"<role>": {"name", "appId",
"objectId", "principalId"}}} (object ids may be missing for identities never created).
"""

import argparse
import datetime
import json
import re
import subprocess
import sys


def az(*args):
    result = subprocess.run(["az", *args, "--only-show-errors", "--output", "json"], capture_output=True, text=True)
    data = None
    if result.returncode == 0 and result.stdout.strip():
        data = json.loads(result.stdout)
    return result.returncode, data, result.stderr


def error_code(err):
    match = re.search(r"\b(Request_[A-Za-z]+|[A-Za-z]*NotFound[A-Za-z]*)\b", err or "")
    return match.group(1) if match else "unrecognised-error"


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--state", required=True)
    parser.add_argument("--subscription", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    state = json.load(open(args.state, encoding="utf-8"))
    sub = args.subscription
    checks = []

    def listing(name, result, empty):
        code, data, err = result
        item = {"check": name, "absent": code == 0 and empty(data)}
        if code:
            item["errorCode"] = error_code(err)
        checks.append(item)

    def exact(name, result, *not_found):
        code, _, err = result
        found_code = error_code(err) if code else None
        checks.append({"check": name, "absent": code != 0 and found_code in not_found,
                       **({"errorCode": found_code} if code else {})})

    group, workspace, run_id = state["group"], state["workspaceName"], state["runId"]
    listing("resource group " + group, az("group", "exists", "--name", group, "--subscription", sub),
            lambda data: data is False)
    listing("resources tagged RunId=" + run_id, az("resource", "list", "--tag", "RunId=" + run_id, "--subscription", sub),
            lambda data: not data)
    exact("workspace " + workspace,
          az("monitor", "log-analytics", "workspace", "show", "--resource-group", group,
             "--workspace-name", workspace, "--subscription", sub),
          "ResourceGroupNotFound", "ResourceNotFound")
    listing("soft-deleted workspace " + workspace + " in " + group,
            az("monitor", "log-analytics", "workspace", "list-deleted-workspaces", "--subscription", sub),
            lambda data: not [item for item in data or []
                              if item.get("name") == workspace and f"/resourceGroups/{group}/".lower() in item.get("id", "").lower()])
    for role, identity in state["identities"].items():
        # `--display-name` matches by prefix: only an exact name counts as this run's app.
        listing(f"{role} application {identity['name']}", az("ad", "app", "list", "--display-name", identity["name"]),
                lambda data: not [item for item in data or [] if item.get("displayName") == identity["name"]])
        listing(f"{role} service principal {identity['name']}", az("ad", "sp", "list", "--display-name", identity["name"]),
                lambda data: not [item for item in data or [] if item.get("displayName") == identity["name"]])
        for kind in ("objectId", "principalId"):
            if identity.get(kind):
                # Only Graph's not-found proves the soft-deleted object was purged.
                exact(f"{role} deleted-items {kind} {identity[kind]}",
                      az("rest", "--method", "get", "--url",
                         "https://graph.microsoft.com/v1.0/directory/deletedItems/" + identity[kind]),
                      "Request_ResourceNotFound")
        if identity.get("principalId"):
            listing(f"{role} role assignments", az("role", "assignment", "list", "--all", "--assignee-object-id",
                                                   identity["principalId"], "--subscription", sub),
                    lambda data: not data)

    result = {"schemaVersion": 1, "runId": run_id, "checkedAt": datetime.datetime.now(datetime.timezone.utc).isoformat(),
              "azureSubscription": sub, "awsResourcesUsed": False, "checks": checks,
              "allAbsent": all(item["absent"] for item in checks)}
    with open(args.output, "w", encoding="utf-8") as output:
        output.write(json.dumps(result, indent=1) + "\n")
    print(json.dumps({"checks": len(checks), "allAbsent": result["allAbsent"],
                      "remaining": [item["check"] for item in checks if not item["absent"]]}))
    return 0 if result["allAbsent"] else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
