#!/usr/bin/env python3
"""Validate Bower's Microsoft Sentinel Content Hub solution, ARM templates, Bicep and KQL.

Checks performed:
  1. Bicep lint and build for deploy/bicep/*.bicep and deploy/sentinel/**/*.bicep
     (when Azure CLI Bicep is installed; required in CI via --require-bicep).
  2. deploy/sentinel/azuredeploy.json schema, parameters (workspaceName, location)
     and exact parity with `az bicep build deploy/sentinel/deploy-to-azure.bicep`.
  3. Solutions/Bower/Data/Solution_Bower.json and SolutionMetadata.json completeness.
  4. Azure-Sentinel YAML schema validation for Analytic Rules, Hunting Queries and Parsers:
     GUIDs, requiredDataConnectors, queryFrequency/queryPeriod, severity, MITRE tactics
     and techniques, entityMappings columns, customDetails columns, and parser parity.
  5. Workbook and Data Connector JSON schema validation.
  6. Content Hub V3 Package/mainTemplate.json and createUiDefinition.json ARM/UI schema
     validation, arm-ttk-style checks, and drift check against build_solution.py.
  7. KQL syntactic sanity checks across all packaged and raw .kql queries, plus secret/
     placeholder leak checks.
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import tempfile
import uuid
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
SOLUTION_DIR = REPO_ROOT / "Solutions" / "Bower"
DEPLOY_SENTINEL = REPO_ROOT / "deploy" / "sentinel"

sys.path.insert(0, str(Path(__file__).resolve().parent))
import build_solution  # noqa: E402

ALLOWED_SEVERITIES = {"High", "Medium", "Low", "Informational"}
ALLOWED_OPERATORS = {"gt", "lt", "eq", "ne"}
ALLOWED_TACTICS = {
    "Reconnaissance",
    "ResourceDevelopment",
    "InitialAccess",
    "Execution",
    "Persistence",
    "PrivilegeEscalation",
    "DefenseEvasion",
    "CredentialAccess",
    "Discovery",
    "LateralMovement",
    "Collection",
    "CommandAndControl",
    "Exfiltration",
    "Impact",
    "ImpairProcessControl",
    "InhibitResponseFunction",
}
ALLOWED_ENTITY_TYPES = {
    "Account",
    "Host",
    "IP",
    "Malware",
    "File",
    "Process",
    "CloudApplication",
    "DNS",
    "AzureResource",
    "FileHash",
    "RegistryKey",
    "RegistryValue",
    "SecurityGroup",
    "URL",
    "Mailbox",
    "MailCluster",
    "MailMessage",
    "SubmissionMail",
}
DURATION_RE = re.compile(r"^\d+[dhm]$")
TECHNIQUE_RE = re.compile(r"^T\d{4}(\.\d{3})?$")
SEMVER_RE = re.compile(r"^\d+\.\d+\.\d+$")
PLACEHOLDER_RE = re.compile(r"__[A-Z][A-Z0-9_]+__")
SECRET_PATTERNS = [
    re.compile(r"(?i)DefaultEndpointsProtocol=https;AccountName="),
    re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
    re.compile(r"(?i)SharedAccessKey=[A-Za-z0-9+/=]{20,}"),
]

ANALYTIC_SOURCE_PARITY = {
    "BowerWecBruteForce.yaml": ("deploy/sentinel/analytics/rules/wec-brute-force.kql", {}),
    "BowerFirewallDeny.yaml": ("deploy/sentinel/analytics/rules/firewall-deny.kql", {}),
    "BowerEventsBeyondTolerance.yaml": ("deploy/sentinel/analytics/rules/beyond-tolerance.kql", {}),
    "BowerAsvsPasswordSpray.yaml": ("deploy/sentinel/analytics/rules/asvs/password-spray.kql", {}),
    "BowerAsvsPrivilegeChange.yaml": ("deploy/sentinel/analytics/rules/asvs/privilege-change.kql", {}),
    "BowerAsvsAdminAfterHours.yaml": ("deploy/sentinel/analytics/rules/asvs/admin-after-hours.kql", {}),
    "BowerAsvsMassExport.yaml": ("deploy/sentinel/analytics/rules/asvs/mass-export.kql", {}),
    "BowerAsvsLogSilence.yaml": ("deploy/sentinel/analytics/rules/asvs/log-silence.kql", {}),
    "BowerCollectorHealthMissing.yaml": (
        "deploy/sentinel/monitoring/queries/collector-health-missing.kql",
        {"__MISSING_MINUTES__": "15", "__EXPECTED_COLLECTORS__": "[]"},
    ),
    "BowerSourceSilentAtDestination.yaml": (
        "deploy/sentinel/monitoring/queries/destination-freshness.kql",
        {"__SILENCE_MINUTES__": "60", "__SILENCE_OVERRIDES__": "[]"},
    ),
}

PARSER_SOURCE_PARITY = {
    "BowerSecurityEvents.yaml": "deploy/sentinel/analytics/bower-security-events.kql",
    "BowerSecurityEventsOfType.yaml": "deploy/sentinel/analytics/bower-security-events-of-type.kql",
}


def strip_kql_comments(kql: str) -> str:
    lines = []
    for raw in kql.replace("\r\n", "\n").splitlines():
        if raw.lstrip().startswith("//"):
            continue
        lines.append(raw.rstrip())
    return "\n".join(line for line in lines if line.strip())


def check_kql_syntax(kql: str, label: str, allow_placeholders: bool = False) -> list[str]:
    """Perform lexical/structural KQL sanity checks."""
    errors: list[str] = []
    code = strip_kql_comments(kql)
    if not code:
        return [f"{label}: KQL query is empty"]

    if not allow_placeholders and PLACEHOLDER_RE.search(code):
        errors.append(f"{label}: unresolved placeholder token found in KQL")

    for pattern in SECRET_PATTERNS:
        if pattern.search(kql):
            errors.append(f"{label}: suspicious secret literal found")

    # Strip workbook template parameters like {CollectorId} before brace balance check
    scan_text = re.sub(r"\{[A-Za-z0-9_:]+\}", "0", code)

    stack: list[str] = []
    pairs = {")": "(", "]": "[", "}": "{"}
    in_quote: str | None = None
    escaped = False
    for ch in scan_text:
        if in_quote:
            if escaped:
                escaped = False
            elif ch == "\\":
                escaped = True
            elif ch == in_quote:
                in_quote = None
            continue
        if ch in ('"', "'"):
            in_quote = ch
        elif ch in "([{":
            stack.append(ch)
        elif ch in ")]}":
            if not stack or stack[-1] != pairs[ch]:
                errors.append(f"{label}: unbalanced delimiter {ch!r} in KQL")
                break
            stack.pop()
    if in_quote:
        errors.append(f"{label}: unterminated string literal ({in_quote}) in KQL")
    if stack:
        errors.append(f"{label}: unclosed delimiter(s) {''.join(stack)!r} in KQL")

    non_empty_lines = [line.strip() for line in code.splitlines() if line.strip()]
    if non_empty_lines[0].startswith("|"):
        errors.append(f"{label}: KQL query starts with a pipe operator '|'")
    if non_empty_lines[-1].endswith("|"):
        errors.append(f"{label}: KQL query ends with a trailing pipe operator '|'")

    return errors


def validate_uuid(value: object, label: str) -> list[str]:
    if not isinstance(value, str):
        return [f"{label}: id must be a string UUID"]
    try:
        parsed = uuid.UUID(value)
    except ValueError:
        return [f"{label}: invalid UUID {value!r}"]
    if str(parsed) != value.lower():
        return [f"{label}: UUID {value!r} must be canonical hyphenated format"]
    return []


def validate_bicep_and_azuredeploy(require_bicep: bool) -> list[str]:
    errors: list[str] = []
    azuredeploy_path = DEPLOY_SENTINEL / "azuredeploy.json"
    if not azuredeploy_path.exists():
        return [f"Missing compiled ARM template: {azuredeploy_path.relative_to(REPO_ROOT)}"]

    try:
        arm = json.loads(azuredeploy_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        return [f"deploy/sentinel/azuredeploy.json: invalid JSON: {exc}"]

    if not arm.get("$schema", "").startswith("https://schema.management.azure.com/schemas/"):
        errors.append("deploy/sentinel/azuredeploy.json: missing valid ARM $schema")
    params = arm.get("parameters", {})
    for required_param in ("workspaceName", "location"):
        if required_param not in params:
            errors.append(f"deploy/sentinel/azuredeploy.json: missing required parameter {required_param!r}")
    for pname, pdef in params.items():
        if not pdef.get("metadata", {}).get("description"):
            errors.append(f"deploy/sentinel/azuredeploy.json: parameter {pname!r} missing metadata.description")
    if not arm.get("resources"):
        errors.append("deploy/sentinel/azuredeploy.json: resources array is empty")

    az = shutil.which("az")
    bicep_ok = False
    if az:
        probe = subprocess.run([az, "bicep", "version"], capture_output=True, text=True)
        bicep_ok = probe.returncode == 0
    if not bicep_ok:
        if require_bicep:
            errors.append("Azure CLI Bicep (`az bicep`) is required but not available")
        return errors

    bicep_files = sorted(
        list((REPO_ROOT / "deploy" / "bicep").glob("*.bicep"))
        + list(DEPLOY_SENTINEL.rglob("*.bicep"))
    )
    for bf in bicep_files:
        rel = bf.relative_to(REPO_ROOT)
        lint = subprocess.run([az, "bicep", "lint", "--file", str(bf)], capture_output=True, text=True)
        if lint.returncode != 0:
            errors.append(f"{rel}: az bicep lint failed:\n{lint.stdout}{lint.stderr}")

    with tempfile.TemporaryDirectory() as tmpdir:
        rebuilt = Path(tmpdir) / "azuredeploy.json"
        build = subprocess.run(
            [az, "bicep", "build", "--file", str(DEPLOY_SENTINEL / "deploy-to-azure.bicep"), "--outfile", str(rebuilt)],
            capture_output=True,
            text=True,
        )
        if build.returncode != 0:
            errors.append(f"deploy/sentinel/deploy-to-azure.bicep: az bicep build failed:\n{build.stdout}{build.stderr}")
        else:
            expected_obj = json.loads(rebuilt.read_text(encoding="utf-8"))
            # Ignore generator version metadata so minor Bicep CLI patch differences in CI do not cause false drift.
            for obj in (arm, expected_obj):
                obj.get("metadata", {}).pop("_generator", None)
                for res in obj.get("resources", []):
                    tpl = res.get("properties", {}).get("template")
                    if isinstance(tpl, dict):
                        tpl.get("metadata", {}).pop("_generator", None)
            if arm != expected_obj:
                errors.append(
                    "deploy/sentinel/azuredeploy.json is out of sync with deploy/sentinel/deploy-to-azure.bicep "
                    "(run: az bicep build --file deploy/sentinel/deploy-to-azure.bicep --outfile deploy/sentinel/azuredeploy.json)"
                )

    return errors


def validate_solution() -> list[str]:
    errors: list[str] = []
    data_path = SOLUTION_DIR / "Data" / "Solution_Bower.json"
    if not data_path.exists():
        return ["Missing Solutions/Bower/Data/Solution_Bower.json"]

    solution = json.loads(data_path.read_text(encoding="utf-8"))
    for key in ("Name", "Author", "Description", "Version", "Metadata", "BasePath"):
        if not solution.get(key):
            errors.append(f"Solution_Bower.json: missing required field {key!r}")

    meta_path = SOLUTION_DIR / solution["Metadata"]
    if not meta_path.exists():
        errors.append(f"Solution_Bower.json: referenced Metadata file missing: {solution['Metadata']}")
    else:
        meta = json.loads(meta_path.read_text(encoding="utf-8"))
        for key in ("publisherId", "offerId", "firstPublishDate", "providers", "categories", "support"):
            if not meta.get(key):
                errors.append(f"SolutionMetadata.json: missing required field {key!r}")

    seen_ids: dict[str, str] = {}

    def record_id(uid: str, where: str) -> None:
        if uid in seen_ids:
            errors.append(f"{where}: duplicate UUID {uid!r} (already used by {seen_ids[uid]})")
        else:
            seen_ids[uid] = where

    # Verify manifest lists match files on disk (no missing or orphaned files)
    manifest_sections = {
        "Data Connectors": ("Data Connectors", "*.json"),
        "Parsers": ("Parsers", "*.yaml"),
        "Workbooks": ("Workbooks", "*.json"),
        "Analytic Rules": ("Analytic Rules", "*.yaml"),
        "Hunting Queries": ("Hunting Queries", "*.yaml"),
    }
    for section, (folder, glob_pat) in manifest_sections.items():
        listed = set(solution.get(section, []))
        on_disk = {f"{folder}/{p.name}" for p in (SOLUTION_DIR / folder).glob(glob_pat)}
        for missing in sorted(listed - on_disk):
            errors.append(f"Solution_Bower.json[{section}]: missing file Solutions/Bower/{missing}")
        for orphan in sorted(on_disk - listed):
            errors.append(f"Solution_Bower.json[{section}]: unreferenced file Solutions/Bower/{orphan}")

    # Validate Data Connectors
    for rel in solution.get("Data Connectors", []):
        path = SOLUTION_DIR / rel
        if not path.exists():
            continue
        dc = json.loads(path.read_text(encoding="utf-8"))
        for field in ("id", "title", "publisher", "dataTypes", "connectivityCriterias", "instructionSteps"):
            if not dc.get(field):
                errors.append(f"{rel}: missing required field {field!r}")
        for sq in dc.get("sampleQueries", []):
            errors.extend(check_kql_syntax(sq.get("query", ""), f"{rel}[sampleQuery:{sq.get('description')}]"))
        for dt in dc.get("dataTypes", []):
            errors.extend(check_kql_syntax(dt.get("lastDataReceivedQuery", ""), f"{rel}[dataType:{dt.get('name')}]"))

    # Validate Parsers
    for rel in solution.get("Parsers", []):
        path = SOLUTION_DIR / rel
        if not path.exists():
            continue
        parser = yaml.safe_load(path.read_text(encoding="utf-8"))
        errors.extend(validate_uuid(parser.get("id"), rel))
        if isinstance(parser.get("id"), str):
            record_id(parser["id"].lower(), rel)
        func = parser.get("Function") or {}
        for field in ("Title", "Version", "LastUpdated"):
            if not func.get(field):
                errors.append(f"{rel}: Function.{field} is required")
        for field in ("Category", "FunctionName", "FunctionAlias", "FunctionQuery"):
            if not parser.get(field):
                errors.append(f"{rel}: missing required field {field!r}")
        errors.extend(check_kql_syntax(parser.get("FunctionQuery", ""), rel))
        if path.name in PARSER_SOURCE_PARITY:
            src_kql = (REPO_ROOT / PARSER_SOURCE_PARITY[path.name]).read_text(encoding="utf-8")
            if strip_kql_comments(parser.get("FunctionQuery", "")) != strip_kql_comments(src_kql):
                errors.append(f"{rel}: FunctionQuery drifted from {PARSER_SOURCE_PARITY[path.name]}")

    # Validate Analytic Rules
    for rel in solution.get("Analytic Rules", []):
        path = SOLUTION_DIR / rel
        if not path.exists():
            continue
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        errors.extend(validate_uuid(rule.get("id"), rel))
        if isinstance(rule.get("id"), str):
            record_id(rule["id"].lower(), rel)
        for field in ("name", "description", "severity", "status", "requiredDataConnectors",
                      "queryFrequency", "queryPeriod", "triggerOperator", "query", "version", "kind"):
            if rule.get(field) is None or rule.get(field) == "":
                errors.append(f"{rel}: missing required field {field!r}")
        if rule.get("severity") not in ALLOWED_SEVERITIES:
            errors.append(f"{rel}: invalid severity {rule.get('severity')!r}")
        if rule.get("kind") != "Scheduled":
            errors.append(f"{rel}: expected kind 'Scheduled', got {rule.get('kind')!r}")
        if rule.get("triggerOperator") not in ALLOWED_OPERATORS:
            errors.append(f"{rel}: invalid triggerOperator {rule.get('triggerOperator')!r}")
        if not isinstance(rule.get("triggerThreshold"), int):
            errors.append(f"{rel}: triggerThreshold must be an integer")
        if not DURATION_RE.match(str(rule.get("queryFrequency", ""))):
            errors.append(f"{rel}: invalid queryFrequency {rule.get('queryFrequency')!r}")
        if not DURATION_RE.match(str(rule.get("queryPeriod", ""))):
            errors.append(f"{rel}: invalid queryPeriod {rule.get('queryPeriod')!r}")
        if not SEMVER_RE.match(str(rule.get("version", ""))):
            errors.append(f"{rel}: invalid semver version {rule.get('version')!r}")
        rdc = rule.get("requiredDataConnectors", [])
        if not isinstance(rdc, list) or not rdc:
            errors.append(f"{rel}: requiredDataConnectors must be a non-empty list")
        else:
            for item in rdc:
                if not item.get("connectorId") or not item.get("dataTypes"):
                    errors.append(f"{rel}: requiredDataConnectors entry needs connectorId and dataTypes")
        for tactic in rule.get("tactics", []):
            if tactic not in ALLOWED_TACTICS:
                errors.append(f"{rel}: unknown MITRE tactic {tactic!r}")
        for tech in rule.get("relevantTechniques", []):
            if not TECHNIQUE_RE.match(str(tech)):
                errors.append(f"{rel}: invalid MITRE technique {tech!r}")
        query = str(rule.get("query", ""))
        errors.extend(check_kql_syntax(query, rel))
        em = rule.get("entityMappings", [])
        if not isinstance(em, list) or not em:
            errors.append(f"{rel}: entityMappings must be a non-empty list")
        for mapping in em:
            if mapping.get("entityType") not in ALLOWED_ENTITY_TYPES:
                errors.append(f"{rel}: invalid entityType {mapping.get('entityType')!r}")
            for fm in mapping.get("fieldMappings", []):
                col = fm.get("columnName", "")
                if not col or not re.search(rf"\b{re.escape(col)}\b", query):
                    errors.append(f"{rel}: entityMapping columnName {col!r} not found in query")
        for detail_key, detail_col in (rule.get("customDetails") or {}).items():
            if not re.search(rf"\b{re.escape(str(detail_col))}\b", query):
                errors.append(f"{rel}: customDetails[{detail_key!r}] column {detail_col!r} not found in query")
        if path.name in ANALYTIC_SOURCE_PARITY:
            src_rel, replacements = ANALYTIC_SOURCE_PARITY[path.name]
            src_kql = (REPO_ROOT / src_rel).read_text(encoding="utf-8")
            for k, v in replacements.items():
                src_kql = src_kql.replace(k, v)
            src_code = strip_kql_comments(src_kql)
            rule_code = strip_kql_comments(query)
            if replacements:
                # Health rules append the Sentinel string-cast extend line from sentinel-health-rules.bicep
                if not rule_code.startswith(src_code):
                    errors.append(f"{rel}: query drifted from {src_rel}")
            elif rule_code != src_code:
                errors.append(f"{rel}: query drifted from {src_rel}")

    # Validate Hunting Queries
    forbidden_hq_keys = {"kind", "severity", "queryFrequency", "queryPeriod", "triggerOperator", "triggerThreshold"}
    for rel in solution.get("Hunting Queries", []):
        path = SOLUTION_DIR / rel
        if not path.exists():
            continue
        hq = yaml.safe_load(path.read_text(encoding="utf-8"))
        errors.extend(validate_uuid(hq.get("id"), rel))
        if isinstance(hq.get("id"), str):
            record_id(hq["id"].lower(), rel)
        for bad in sorted(forbidden_hq_keys & set(hq.keys())):
            errors.append(f"{rel}: hunting query must not contain analytic-only key {bad!r}")
        for field in ("name", "description", "requiredDataConnectors", "tactics", "query", "version"):
            if not hq.get(field):
                errors.append(f"{rel}: missing required field {field!r}")
        for tactic in hq.get("tactics", []):
            if tactic not in ALLOWED_TACTICS:
                errors.append(f"{rel}: unknown MITRE tactic {tactic!r}")
        for tech in hq.get("relevantTechniques", []):
            if not TECHNIQUE_RE.match(str(tech)):
                errors.append(f"{rel}: invalid MITRE technique {tech!r}")
        query = str(hq.get("query", ""))
        errors.extend(check_kql_syntax(query, rel))
        for mapping in hq.get("entityMappings", []):
            if mapping.get("entityType") not in ALLOWED_ENTITY_TYPES:
                errors.append(f"{rel}: invalid entityType {mapping.get('entityType')!r}")
            for fm in mapping.get("fieldMappings", []):
                col = fm.get("columnName", "")
                if not col or not re.search(rf"\b{re.escape(col)}\b", query):
                    errors.append(f"{rel}: entityMapping columnName {col!r} not found in query")

    # Validate Workbooks
    for rel in solution.get("Workbooks", []):
        path = SOLUTION_DIR / rel
        if not path.exists():
            continue
        wb = json.loads(path.read_text(encoding="utf-8"))
        if wb.get("version") != "Notebook/1.0":
            errors.append(f"{rel}: expected workbook version 'Notebook/1.0'")
        items = wb.get("items", [])
        if not items:
            errors.append(f"{rel}: workbook has no items")
        for item in items:
            content = item.get("content", {})
            if item.get("type") == 3 and "query" in content:
                errors.extend(check_kql_syntax(content["query"], f"{rel}[{item.get('name')}]"))
            elif item.get("type") == 9:
                for param in content.get("parameters", []):
                    if param.get("query"):
                        errors.extend(check_kql_syntax(param["query"], f"{rel}[param:{param.get('name')}]"))

    # Validate Package/mainTemplate.json and createUiDefinition.json (arm-ttk-style checks + drift)
    mt_path = SOLUTION_DIR / "Package" / "mainTemplate.json"
    ui_path = SOLUTION_DIR / "Package" / "createUiDefinition.json"
    if not mt_path.exists() or not ui_path.exists():
        errors.append("Missing Solutions/Bower/Package/mainTemplate.json or createUiDefinition.json")
    else:
        mt = json.loads(mt_path.read_text(encoding="utf-8"))
        ui = json.loads(ui_path.read_text(encoding="utf-8"))
        if mt.get("$schema") != build_solution.ARM_SCHEMA:
            errors.append("Package/mainTemplate.json: unexpected $schema")
        if "workspace" not in mt.get("parameters", {}) or "workspace-location" not in mt.get("parameters", {}):
            errors.append("Package/mainTemplate.json: missing workspace or workspace-location parameter")
        for pname, pdef in mt.get("parameters", {}).items():
            if not pdef.get("metadata", {}).get("description"):
                errors.append(f"Package/mainTemplate.json: parameter {pname!r} missing description")
        types = [r.get("type") for r in mt.get("resources", [])]
        if "Microsoft.OperationalInsights/workspaces/providers/contentPackages" not in types:
            errors.append("Package/mainTemplate.json: missing contentPackages resource")
        if "Microsoft.OperationalInsights/workspaces/providers/contentTemplates" not in types:
            errors.append("Package/mainTemplate.json: missing contentTemplates resources")
        if ui.get("handler") != "Microsoft.Azure.CreateUIDef":
            errors.append("Package/createUiDefinition.json: unexpected handler")
        ui_outputs = ui.get("parameters", {}).get("outputs", {})
        for out_key in ("workspace", "workspace-location", "location"):
            if out_key not in ui_outputs:
                errors.append(f"Package/createUiDefinition.json: missing output {out_key!r}")
        if build_solution.main(["--check"]) != 0:
            errors.append("Solutions/Bower/Package/ drifted from tools/sentinel/build_solution.py")

    # Validate raw .kql files under deploy/sentinel/
    for kql_path in sorted(DEPLOY_SENTINEL.rglob("*.kql")):
        rel = str(kql_path.relative_to(REPO_ROOT))
        allow_ph = "deploy/sentinel/monitoring/queries/" in rel
        errors.extend(check_kql_syntax(kql_path.read_text(encoding="utf-8"), rel, allow_placeholders=allow_ph))

    return errors


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--require-bicep",
        action="store_true",
        help="Fail if Azure CLI Bicep (`az bicep`) is not available.",
    )
    args = parser.parse_args(argv)

    errors = []
    errors.extend(validate_bicep_and_azuredeploy(require_bicep=args.require_bicep))
    errors.extend(validate_solution())

    if errors:
        print("Sentinel packaging validation failed:", file=sys.stderr)
        for err in errors:
            print(f"  - {err}", file=sys.stderr)
        return 1

    print("All Microsoft Sentinel templates, Content Hub V3 files, YAML rules and KQL checks passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
