#!/usr/bin/env python3
"""Show that duplicate Sentinel rows collapse with the documented deduplication query.

For each scenario attempt directory, runs (with the separate verifier identity, through
query-firewall.py's guarded client) the R9 query over the plan's collector and time window:
raw rows, rows after `summarize arg_min(ingestion_time(), *) by EventId`, and distinct ids.
Writes dedup-proof.json beside the attempt's other evidence; counts only.
"""

import argparse
import datetime as dt
import importlib.util
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("query_firewall", HERE / "query-firewall.py")
query = importlib.util.module_from_spec(spec)
spec.loader.exec_module(query)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--azure-state-dir", type=Path, required=True)
    parser.add_argument("attempts", type=Path, nargs="+")
    args = parser.parse_args()
    for attempt in args.attempts:
        plan = query.read_json(attempt / "plan.json")
        query.expected(plan)  # Validates every interpolated value.
        text = '''let scoped = BowerSecurity_CL
| where CollectorId == "{collector}" and ApplicationName == "nftables-firewall"
    and ApplicationEnvironment == "validation" and EventType == "network_connection_denied"
| where TimeGenerated between (datetime({start}) .. datetime({end}));
let collapsed = scoped | summarize arg_min(ingestion_time(), *) by EventId;
print RawRows = toscalar(scoped | count), CollapsedRows = toscalar(collapsed | count),
    DistinctIds = toscalar(scoped | summarize count() by EventId | count)'''.format(
            collector=plan["collectorId"], start=query.iso(plan["startEpoch"] - 2),
            end=query.iso(plan["collectNotBeforeEpoch"]))
        data, workspace, verifier = query.query_live(args.azure_state_dir, text)
        table = data["tables"][0]
        values = dict(zip([column["name"] for column in table["columns"]], table["rows"][0]))
        result = {"schemaVersion": 1, "scenario": plan["scenario"], "query": text,
                  "queriedAt": dt.datetime.now(dt.timezone.utc).isoformat(), "workspaceId": workspace,
                  "verifierClientId": verifier, **values,
                  "duplicateRows": values["RawRows"] - values["DistinctIds"],
                  "collapses": values["CollapsedRows"] == values["DistinctIds"] == len(query.expected(plan))}
        (attempt / "dedup-proof.json").write_text(json.dumps(result, indent=1) + "\n")
        print(json.dumps({key: result[key] for key in ("scenario", "RawRows", "CollapsedRows", "DistinctIds", "collapses")}))


if __name__ == "__main__":
    main()
