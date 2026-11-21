#!/usr/bin/env python3
"""Generate official Microsoft Sentinel Content Hub V3 package files for Bower.

Reads Solutions/Bower/Data/Solution_Bower.json, SolutionMetadata.json, and all
referenced Data Connectors, Parsers, Workbooks, Hunting Queries and Analytic Rules
and writes:
  - Solutions/Bower/Package/mainTemplate.json
  - Solutions/Bower/Package/createUiDefinition.json

Pass --check to verify the committed Package/ files match the generated output.
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import sys
import uuid
import yaml

REPO_ROOT = Path(__file__).resolve().parents[2]
SOLUTION_DIR = REPO_ROOT / "Solutions" / "Bower"
DATA_FILE = SOLUTION_DIR / "Data" / "Solution_Bower.json"
PACKAGE_DIR = SOLUTION_DIR / "Package"

ARM_SCHEMA = "https://schema.management.azure.com/schemas/2019-04-01/deploymentTemplate.json#"
UI_SCHEMA = "https://schema.management.azure.com/schemas/0.1.2-preview/CreateUIDefinition.MultiVm.json#"

OPERATOR_MAP = {
    "gt": "GreaterThan",
    "lt": "LessThan",
    "eq": "Equal",
    "ne": "NotEqual",
}


def duration_to_iso8601(value: str) -> str:
    """Convert Azure-Sentinel YAML shorthand (5m, 15m, 1h, 1d, 450m) to ISO 8601."""
    if value.startswith("P"):
        return value
    match = re.fullmatch(r"(\d+)([dhm])", value.strip())
    if not match:
        raise ValueError(f"Unsupported duration format: {value!r}")
    amount, unit = match.group(1), match.group(2)
    if unit == "d":
        return f"P{amount}D"
    if unit == "h":
        return f"PT{amount}H"
    return f"PT{amount}M"


def short_hash(seed: str) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:12]


def deterministic_guid(seed: str) -> str:
    return str(uuid.uuid5(uuid.NAMESPACE_URL, f"https://github.com/jusso-dev/Bower/sentinel/{seed}"))


def load_solution() -> tuple[dict, dict]:
    solution = json.loads(DATA_FILE.read_text(encoding="utf-8"))
    metadata = json.loads((SOLUTION_DIR / solution["Metadata"]).read_text(encoding="utf-8"))
    return solution, metadata


def build_main_template(solution: dict, metadata: dict) -> dict:
    solution_id = f"{metadata['publisherId']}.{metadata['offerId']}"
    solution_version = solution["Version"]
    solution_name = solution["Name"]
    author_name = solution["Author"]
    support = metadata["support"]
    categories = metadata["categories"]

    connectors = [
        json.loads((SOLUTION_DIR / rel).read_text(encoding="utf-8"))
        for rel in solution.get("Data Connectors", [])
    ]
    parsers = [
        yaml.safe_load((SOLUTION_DIR / rel).read_text(encoding="utf-8"))
        for rel in solution.get("Parsers", [])
    ]
    workbooks = [
        (rel, json.loads((SOLUTION_DIR / rel).read_text(encoding="utf-8")))
        for rel in solution.get("Workbooks", [])
    ]
    hunting_queries = [
        yaml.safe_load((SOLUTION_DIR / rel).read_text(encoding="utf-8"))
        for rel in solution.get("Hunting Queries", [])
    ]
    analytic_rules = [
        yaml.safe_load((SOLUTION_DIR / rel).read_text(encoding="utf-8"))
        for rel in solution.get("Analytic Rules", [])
    ]

    parameters: dict = {
        "location": {
            "type": "string",
            "minLength": 1,
            "defaultValue": "[resourceGroup().location]",
            "metadata": {
                "description": "Not used directly; retained for ARM template checks. Resources use workspace-location."
            },
        },
        "workspace-location": {
            "type": "string",
            "minLength": 1,
            "defaultValue": "[parameters('location')]",
            "metadata": {
                "description": "Azure region of the target Log Analytics workspace."
            },
        },
        "workspace": {
            "type": "string",
            "minLength": 1,
            "metadata": {
                "description": "Existing Log Analytics workspace name with Microsoft Sentinel enabled."
            },
        },
    }

    for idx, (rel, _wb) in enumerate(workbooks, start=1):
        parameters[f"workbook{idx}-name"] = {
            "type": "string",
            "defaultValue": "Bower Security Operations and Pipeline Health",
            "minLength": 1,
            "metadata": {
                "description": f"Display name for workbook from {rel}."
            },
        }

    variables: dict = {
        "_solutionName": solution_name,
        "_solutionVersion": solution_version,
        "_solutionId": solution_id,
        "_solutionAuthor": author_name,
        "_solutionTier": support["tier"],
        "_solutionContentProductId": f"{solution_id[:50]}-sl-{short_hash(solution_id)}",
    }

    package_dep = "[extensionResourceId(resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace')), 'Microsoft.SecurityInsights/contentPackages', variables('_solutionId'))]"
    package_dependencies: list[dict] = []
    resources: list[dict] = []

    # 1. Data Connectors
    for idx, connector in enumerate(connectors, start=1):
        cid = connector["id"]
        content_product_id = f"{solution_id[:50]}-dc-{short_hash(cid)}"
        version = "1.0.0"
        var_key = f"dataConnectorObject{idx}"
        variables[var_key] = {
            "contentId": cid,
            "version": version,
            "contentProductId": content_product_id,
            "templateSpecName": f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/', concat(parameters('workspace'), '-dc-', uniquestring('{cid}')))]",
        }
        package_dependencies.append(
            {
                "contentId": cid,
                "kind": "DataConnector",
                "version": version,
            }
        )
        resources.append(
            {
                "type": "Microsoft.OperationalInsights/workspaces/providers/contentTemplates",
                "apiVersion": "2023-04-01-preview",
                "name": f"[variables('{var_key}').templateSpecName]",
                "location": "[parameters('workspace-location')]",
                "dependsOn": [package_dep],
                "properties": {
                    "description": f"{connector['title']} Data Connector with template version {solution_version}",
                    "mainTemplate": {
                        "$schema": ARM_SCHEMA,
                        "contentVersion": f"[variables('{var_key}').version]",
                        "parameters": {},
                        "variables": {},
                        "resources": [
                            {
                                "type": "Microsoft.OperationalInsights/workspaces/providers/metadata",
                                "apiVersion": "2022-01-01-preview",
                                "name": f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/DataConnector-{cid}')]",
                                "properties": {
                                    "parentId": f"[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace'))]",
                                    "contentId": f"[variables('{var_key}').contentId]",
                                    "kind": "DataConnector",
                                    "version": f"[variables('{var_key}').version]",
                                    "source": {
                                        "kind": "Solution",
                                        "name": "[variables('_solutionName')]",
                                        "sourceId": "[variables('_solutionId')]",
                                    },
                                    "author": {"name": "[variables('_solutionAuthor')]"},
                                    "support": support,
                                },
                            }
                        ],
                    },
                    "packageId": "[variables('_solutionId')]",
                    "packageVersion": "[variables('_solutionVersion')]",
                    "packageName": "[variables('_solutionName')]",
                    "packageKind": "Solution",
                    "contentId": f"[variables('{var_key}').contentId]",
                    "contentProductId": f"[variables('{var_key}').contentProductId]",
                    "contentKind": "DataConnector",
                    "displayName": connector["title"],
                    "contentSchemaVersion": "3.0.0",
                    "icon": "",
                    "version": f"[variables('{var_key}').version]",
                    "source": {
                        "kind": "Solution",
                        "name": "[variables('_solutionName')]",
                        "sourceId": "[variables('_solutionId')]",
                    },
                    "author": {"name": "[variables('_solutionAuthor')]"},
                    "support": support,
                    "categories": categories,
                },
            }
        )

    # 2. Parsers (both live savedSearches and Content Hub contentTemplates)
    for idx, parser in enumerate(parsers, start=1):
        pid = parser["id"]
        alias = parser["FunctionAlias"]
        title = parser["Function"]["Title"]
        version = str(parser["Function"]["Version"])
        query = parser["FunctionQuery"].rstrip("\n")
        func_params = parser.get("FunctionParams")
        saved_search_name = re.sub(r"([a-z0-9])([A-Z])", r"\1-\2", alias).lower()
        content_product_id = f"{solution_id[:50]}-pr-{short_hash(pid)}"
        var_key = f"parserObject{idx}"
        variables[var_key] = {
            "contentId": pid,
            "version": version,
            "contentProductId": content_product_id,
            "savedSearchName": saved_search_name,
            "templateSpecName": f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/', concat(parameters('workspace'), '-pr-', uniquestring('{pid}')))]",
        }
        package_dependencies.append(
            {
                "contentId": pid,
                "kind": "Parser",
                "version": version,
            }
        )
        saved_search_props: dict = {
            "eTag": "*",
            "displayName": title,
            "category": parser.get("Category", "Microsoft Sentinel Parser"),
            "functionAlias": alias,
            "query": query,
            "version": 2,
        }
        if func_params:
            saved_search_props["functionParameters"] = func_params

        resources.append(
            {
                "type": "Microsoft.OperationalInsights/workspaces/savedSearches",
                "apiVersion": "2025-07-01",
                "name": f"[concat(parameters('workspace'), '/', variables('{var_key}').savedSearchName)]",
                "properties": saved_search_props,
            }
        )
        resources.append(
            {
                "type": "Microsoft.OperationalInsights/workspaces/providers/contentTemplates",
                "apiVersion": "2023-04-01-preview",
                "name": f"[variables('{var_key}').templateSpecName]",
                "location": "[parameters('workspace-location')]",
                "dependsOn": [package_dep],
                "properties": {
                    "description": f"{alias} Parser with template version {solution_version}",
                    "mainTemplate": {
                        "$schema": ARM_SCHEMA,
                        "contentVersion": f"[variables('{var_key}').version]",
                        "parameters": {},
                        "variables": {},
                        "resources": [
                            {
                                "type": "Microsoft.OperationalInsights/workspaces/savedSearches",
                                "apiVersion": "2025-07-01",
                                "name": f"[concat(parameters('workspace'), '/', variables('{var_key}').savedSearchName)]",
                                "properties": saved_search_props,
                            }
                        ],
                    },
                    "packageId": "[variables('_solutionId')]",
                    "packageVersion": "[variables('_solutionVersion')]",
                    "packageName": "[variables('_solutionName')]",
                    "packageKind": "Solution",
                    "contentId": f"[variables('{var_key}').contentId]",
                    "contentProductId": f"[variables('{var_key}').contentProductId]",
                    "contentKind": "Parser",
                    "displayName": title,
                    "contentSchemaVersion": "3.0.0",
                    "version": f"[variables('{var_key}').version]",
                    "source": {
                        "kind": "Solution",
                        "name": "[variables('_solutionName')]",
                        "sourceId": "[variables('_solutionId')]",
                    },
                    "author": {"name": "[variables('_solutionAuthor')]"},
                    "support": support,
                    "categories": categories,
                },
            }
        )

    # 3. Workbooks
    for idx, (rel, workbook_data) in enumerate(workbooks, start=1):
        wb_content_id = deterministic_guid(rel)
        wb_version = "1.0.0"
        wb_product_id = f"{solution_id[:50]}-wb-{short_hash(wb_content_id)}"
        var_key = f"workbookObject{idx}"
        variables[var_key] = {
            "contentId": wb_content_id,
            "version": wb_version,
            "contentProductId": wb_product_id,
            "templateSpecName": f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/', concat(parameters('workspace'), '-wb-', uniquestring('{wb_content_id}')))]",
        }
        package_dependencies.append(
            {
                "contentId": wb_content_id,
                "kind": "Workbook",
                "version": wb_version,
            }
        )
        resources.append(
            {
                "type": "Microsoft.OperationalInsights/workspaces/providers/contentTemplates",
                "apiVersion": "2023-04-01-preview",
                "name": f"[variables('{var_key}').templateSpecName]",
                "location": "[parameters('workspace-location')]",
                "dependsOn": [package_dep],
                "properties": {
                    "description": f"Bower Security Operations Workbook with template version {solution_version}",
                    "mainTemplate": {
                        "$schema": ARM_SCHEMA,
                        "contentVersion": f"[variables('{var_key}').version]",
                        "parameters": {},
                        "variables": {},
                        "resources": [
                            {
                                "type": "Microsoft.Insights/workbooks",
                                "apiVersion": "2022-04-01",
                                "name": f"[guid(resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace')), variables('{var_key}').contentId)]",
                                "location": "[parameters('workspace-location')]",
                                "kind": "shared",
                                "properties": {
                                    "displayName": f"[parameters('workbook{idx}-name')]",
                                    "serializedData": json.dumps(workbook_data, separators=(",", ":")),
                                    "version": "1.0",
                                    "sourceId": "[resourceId('Microsoft.OperationalInsights/workspaces', parameters('workspace'))]",
                                    "category": "sentinel",
                                },
                            }
                        ],
                    },
                    "packageId": "[variables('_solutionId')]",
                    "packageVersion": "[variables('_solutionVersion')]",
                    "packageName": "[variables('_solutionName')]",
                    "packageKind": "Solution",
                    "contentId": f"[variables('{var_key}').contentId]",
                    "contentProductId": f"[variables('{var_key}').contentProductId]",
                    "contentKind": "Workbook",
                    "displayName": "Bower Security Operations and Pipeline Health",
                    "contentSchemaVersion": "3.0.0",
                    "version": f"[variables('{var_key}').version]",
                    "source": {
                        "kind": "Solution",
                        "name": "[variables('_solutionName')]",
                        "sourceId": "[variables('_solutionId')]",
                    },
                    "author": {"name": "[variables('_solutionAuthor')]"},
                    "support": support,
                    "categories": categories,
                },
            }
        )

    # 4. Hunting Queries
    for idx, hq in enumerate(hunting_queries, start=1):
        hid = hq["id"]
        hversion = str(hq["version"])
        hproduct_id = f"{solution_id[:50]}-hq-{short_hash(hid)}"
        var_key = f"huntingQueryObject{idx}"
        variables[var_key] = {
            "contentId": hid,
            "version": hversion,
            "contentProductId": hproduct_id,
            "templateSpecName": f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/', concat(parameters('workspace'), '-hq-', uniquestring('{hid}')))]",
        }
        package_dependencies.append(
            {
                "contentId": hid,
                "kind": "HuntingQuery",
                "version": hversion,
            }
        )
        tags = [
            {"name": "description", "value": hq["description"].strip()},
            {"name": "tactics", "value": ",".join(hq.get("tactics", []))},
            {"name": "techniques", "value": ",".join(hq.get("relevantTechniques", []))},
        ]
        resources.append(
            {
                "type": "Microsoft.OperationalInsights/workspaces/providers/contentTemplates",
                "apiVersion": "2023-04-01-preview",
                "name": f"[variables('{var_key}').templateSpecName]",
                "location": "[parameters('workspace-location')]",
                "dependsOn": [package_dep],
                "properties": {
                    "description": f"{hq['name']} Hunting Query with template version {solution_version}",
                    "mainTemplate": {
                        "$schema": ARM_SCHEMA,
                        "contentVersion": f"[variables('{var_key}').version]",
                        "parameters": {},
                        "variables": {},
                        "resources": [
                            {
                                "type": "Microsoft.OperationalInsights/workspaces/savedSearches",
                                "apiVersion": "2025-07-01",
                                "name": f"[concat(parameters('workspace'), '/', variables('{var_key}').contentId)]",
                                "properties": {
                                    "eTag": "*",
                                    "displayName": hq["name"],
                                    "category": "Hunting Queries",
                                    "query": hq["query"].rstrip("\n"),
                                    "version": 2,
                                    "tags": tags,
                                },
                            }
                        ],
                    },
                    "packageId": "[variables('_solutionId')]",
                    "packageVersion": "[variables('_solutionVersion')]",
                    "packageName": "[variables('_solutionName')]",
                    "packageKind": "Solution",
                    "contentId": f"[variables('{var_key}').contentId]",
                    "contentProductId": f"[variables('{var_key}').contentProductId]",
                    "contentKind": "HuntingQuery",
                    "displayName": hq["name"],
                    "contentSchemaVersion": "3.0.0",
                    "version": f"[variables('{var_key}').version]",
                    "source": {
                        "kind": "Solution",
                        "name": "[variables('_solutionName')]",
                        "sourceId": "[variables('_solutionId')]",
                    },
                    "author": {"name": "[variables('_solutionAuthor')]"},
                    "support": support,
                    "categories": categories,
                },
            }
        )

    # 5. Analytic Rules (as templates; disabled by default)
    for idx, rule in enumerate(analytic_rules, start=1):
        rid = rule["id"]
        rversion = str(rule["version"])
        rproduct_id = f"{solution_id[:50]}-ar-{short_hash(rid)}"
        var_key = f"analyticRuleObject{idx}"
        variables[var_key] = {
            "contentId": rid,
            "version": rversion,
            "contentProductId": rproduct_id,
            "templateSpecName": f"[concat(parameters('workspace'), '/Microsoft.SecurityInsights/', concat(parameters('workspace'), '-ar-', uniquestring('{rid}')))]",
        }
        package_dependencies.append(
            {
                "contentId": rid,
                "kind": "AnalyticsRule",
                "version": rversion,
            }
        )
        rule_props: dict = {
            "description": rule["description"].strip(),
            "displayName": rule["name"],
            "enabled": False,
            "query": rule["query"].rstrip("\n"),
            "queryFrequency": duration_to_iso8601(rule["queryFrequency"]),
            "queryPeriod": duration_to_iso8601(rule["queryPeriod"]),
            "severity": rule["severity"],
            "suppressionDuration": "PT5H",
            "suppressionEnabled": False,
            "triggerOperator": OPERATOR_MAP[rule["triggerOperator"]],
            "triggerThreshold": rule["triggerThreshold"],
            "tactics": rule.get("tactics", []),
            "techniques": rule.get("relevantTechniques", []),
            "entityMappings": rule.get("entityMappings", []),
            "eventGroupingSettings": rule.get("eventGroupingSettings", {"aggregationKind": "AlertPerResult"}),
        }
        if "customDetails" in rule:
            rule_props["customDetails"] = rule["customDetails"]
        if "alertDetailsOverride" in rule:
            rule_props["alertDetailsOverride"] = rule["alertDetailsOverride"]
        if "incidentConfiguration" in rule:
            inc = json.loads(json.dumps(rule["incidentConfiguration"]))
            gc = inc.get("groupingConfiguration", {})
            if "lookbackDuration" in gc:
                gc["lookbackDuration"] = duration_to_iso8601(gc["lookbackDuration"])
            rule_props["incidentConfiguration"] = inc

        resources.append(
            {
                "type": "Microsoft.OperationalInsights/workspaces/providers/contentTemplates",
                "apiVersion": "2023-04-01-preview",
                "name": f"[variables('{var_key}').templateSpecName]",
                "location": "[parameters('workspace-location')]",
                "dependsOn": [package_dep],
                "properties": {
                    "description": f"{rule['name']} Analytics Rule with template version {solution_version}",
                    "mainTemplate": {
                        "$schema": ARM_SCHEMA,
                        "contentVersion": f"[variables('{var_key}').version]",
                        "parameters": {},
                        "variables": {},
                        "resources": [
                            {
                                "type": "Microsoft.SecurityInsights/AlertRuleTemplates",
                                "apiVersion": "2023-02-01-preview",
                                "name": f"[variables('{var_key}').contentId]",
                                "kind": rule.get("kind", "Scheduled"),
                                "location": "[parameters('workspace-location')]",
                                "properties": rule_props,
                            }
                        ],
                    },
                    "packageId": "[variables('_solutionId')]",
                    "packageVersion": "[variables('_solutionVersion')]",
                    "packageName": "[variables('_solutionName')]",
                    "packageKind": "Solution",
                    "contentId": f"[variables('{var_key}').contentId]",
                    "contentProductId": f"[variables('{var_key}').contentProductId]",
                    "contentKind": "AnalyticsRule",
                    "displayName": rule["name"],
                    "contentSchemaVersion": "3.0.0",
                    "version": f"[variables('{var_key}').version]",
                    "source": {
                        "kind": "Solution",
                        "name": "[variables('_solutionName')]",
                        "sourceId": "[variables('_solutionId')]",
                    },
                    "author": {"name": "[variables('_solutionAuthor')]"},
                    "support": support,
                    "categories": categories,
                },
            }
        )

    # 6. Content Package resource (must exist for contentTemplates dependencies)
    summary_counts = (
        f"**Data Connectors:** {len(connectors)}, "
        f"**Parsers:** {len(parsers)}, "
        f"**Workbooks:** {len(workbooks)}, "
        f"**Analytic Rules:** {len(analytic_rules)}, "
        f"**Hunting Queries:** {len(hunting_queries)}"
    )
    resources.append(
        {
            "type": "Microsoft.OperationalInsights/workspaces/providers/contentPackages",
            "apiVersion": "2023-04-01-preview",
            "name": "[concat(parameters('workspace'), '/Microsoft.SecurityInsights/', variables('_solutionId'))]",
            "location": "[parameters('workspace-location')]",
            "properties": {
                "version": "[variables('_solutionVersion')]",
                "kind": "Solution",
                "contentSchemaVersion": "3.0.0",
                "displayName": "[variables('_solutionName')]",
                "publisherDisplayName": metadata["providers"][0],
                "descriptionHtml": f"<p>{solution['Description'].replace(chr(10), '<br/>')}</p><p>{summary_counts}</p>",
                "contentKind": "Solution",
                "contentId": "[variables('_solutionId')]",
                "contentProductId": "[variables('_solutionContentProductId')]",
                "id": "[variables('_solutionId')]",
                "icon": "",
                "dependencies": {
                    "operator": "AND",
                    "criteria": package_dependencies,
                },
                "firstPublishDate": metadata["firstPublishDate"],
                "providers": metadata["providers"],
                "categories": categories,
                "support": support,
                "author": {"name": "[variables('_solutionAuthor')]"},
                "source": {
                    "kind": "Solution",
                    "name": "[variables('_solutionName')]",
                    "sourceId": "[variables('_solutionId')]",
                },
            },
        }
    )

    return {
        "$schema": ARM_SCHEMA,
        "contentVersion": "1.0.0.0",
        "metadata": {
            "author": author_name,
            "comments": "Generated by tools/sentinel/build_solution.py in Microsoft Sentinel Content Hub V3 format.",
        },
        "parameters": parameters,
        "variables": variables,
        "resources": resources,
    }


def build_create_ui_definition(solution: dict) -> dict:
    connectors = [
        json.loads((SOLUTION_DIR / rel).read_text(encoding="utf-8"))
        for rel in solution.get("Data Connectors", [])
    ]
    parsers = [
        yaml.safe_load((SOLUTION_DIR / rel).read_text(encoding="utf-8"))
        for rel in solution.get("Parsers", [])
    ]
    workbooks = solution.get("Workbooks", [])
    analytic_rules = [
        yaml.safe_load((SOLUTION_DIR / rel).read_text(encoding="utf-8"))
        for rel in solution.get("Analytic Rules", [])
    ]
    hunting_queries = [
        yaml.safe_load((SOLUTION_DIR / rel).read_text(encoding="utf-8"))
        for rel in solution.get("Hunting Queries", [])
    ]

    steps: list[dict] = [
        {
            "name": "dataconnectors",
            "label": "Data Connectors",
            "bladeTitle": "Data Connectors",
            "elements": [
                {
                    "name": "dataconnectors1-text",
                    "type": "Microsoft.Common.TextBlock",
                    "options": {
                        "text": f"This solution installs the {connectors[0]['title']} data connector guidance for BowerSecurity_CL. Deploy deploy/bicep/main.bicep or deploy/sentinel/azuredeploy.json to provision the table, DCE and DCR."
                    },
                },
                {
                    "name": "dataconnectors-link1",
                    "type": "Microsoft.Common.TextBlock",
                    "options": {
                        "link": {
                            "label": "Bower Logs Ingestion API guide",
                            "uri": "https://github.com/jusso-dev/Bower/blob/main/docs/deployment/logs-ingestion-api.md",
                        }
                    },
                },
            ],
        },
        {
            "name": "parsers",
            "label": "Parsers",
            "bladeTitle": "Parsers",
            "elements": [
                {
                    "name": "parsers-text",
                    "type": "Microsoft.Common.TextBlock",
                    "options": {
                        "text": "This solution installs the replay-safe KQL workspace functions BowerSecurityEvents and BowerSecurityEventsOfType."
                    },
                },
                *[
                    {
                        "name": f"parser{idx}",
                        "type": "Microsoft.Common.Section",
                        "label": parser["FunctionAlias"],
                        "elements": [
                            {
                                "name": f"parser{idx}-text",
                                "type": "Microsoft.Common.TextBlock",
                                "options": {"text": parser["Function"]["Title"]},
                            }
                        ],
                    }
                    for idx, parser in enumerate(parsers, start=1)
                ],
            ],
        },
        {
            "name": "workbooks",
            "label": "Workbooks",
            "subLabel": {
                "preValidation": "Configure the workbooks",
                "postValidation": "Done",
            },
            "bladeTitle": "Workbooks",
            "elements": [
                {
                    "name": "workbooks-text",
                    "type": "Microsoft.Common.TextBlock",
                    "options": {
                        "text": "This Microsoft Sentinel solution installs the Bower Security Operations and Pipeline Health workbook."
                    },
                },
                *[
                    {
                        "name": f"workbook{idx}",
                        "type": "Microsoft.Common.Section",
                        "label": "Bower Security Operations and Pipeline Health",
                        "elements": [
                            {
                                "name": f"workbook{idx}-text",
                                "type": "Microsoft.Common.TextBlock",
                                "options": {
                                    "text": "Monitors collector health, delivery delay, queue backlogs, replay ratios, security event volume, Privacy & Secret Protection Engine alerts, and Sentinel rule health."
                                },
                            }
                        ],
                    }
                    for idx, _wb in enumerate(workbooks, start=1)
                ],
            ],
        },
        {
            "name": "analytics",
            "label": "Analytics",
            "subLabel": {
                "preValidation": "Review the analytics templates",
                "postValidation": "Done",
            },
            "bladeTitle": "Analytics",
            "elements": [
                {
                    "name": "analytics-text",
                    "type": "Microsoft.Common.TextBlock",
                    "options": {
                        "text": "This solution installs the following scheduled analytic rule templates (disabled by default). Validate against live BowerSecurity_CL telemetry before enabling."
                    },
                },
                *[
                    {
                        "name": f"analytic{idx}",
                        "type": "Microsoft.Common.Section",
                        "label": rule["name"],
                        "elements": [
                            {
                                "name": f"analytic{idx}-text",
                                "type": "Microsoft.Common.TextBlock",
                                "options": {"text": rule["description"].strip()},
                            }
                        ],
                    }
                    for idx, rule in enumerate(analytic_rules, start=1)
                ],
            ],
        },
        {
            "name": "huntingqueries",
            "label": "Hunting Queries",
            "bladeTitle": "Hunting Queries",
            "elements": [
                {
                    "name": "huntingqueries-text",
                    "type": "Microsoft.Common.TextBlock",
                    "options": {
                        "text": "This solution installs threat-hunting, delivery reconciliation and sequence-gap queries for BowerSecurity_CL."
                    },
                },
                *[
                    {
                        "name": f"hunting{idx}",
                        "type": "Microsoft.Common.Section",
                        "label": hq["name"],
                        "elements": [
                            {
                                "name": f"hunting{idx}-text",
                                "type": "Microsoft.Common.TextBlock",
                                "options": {"text": hq["description"].strip()},
                            }
                        ],
                    }
                    for idx, hq in enumerate(hunting_queries, start=1)
                ],
            ],
        },
    ]

    summary = (
        f"**Data Connectors:** {len(connectors)}, "
        f"**Parsers:** {len(parsers)}, "
        f"**Workbooks:** {len(workbooks)}, "
        f"**Analytic Rules:** {len(analytic_rules)}, "
        f"**Hunting Queries:** {len(hunting_queries)}"
    )

    return {
        "$schema": UI_SCHEMA,
        "handler": "Microsoft.Azure.CreateUIDef",
        "version": "0.1.2-preview",
        "parameters": {
            "config": {
                "isWizard": False,
                "basics": {
                    "description": (
                        f"{solution['Logo']}\n\n"
                        f"**Note:** Review the [Release Notes](https://github.com/jusso-dev/Bower/blob/main/Solutions/Bower/ReleaseNotes.md) before installing.\n\n"
                        f"{solution['Description']}\n\n"
                        f"{summary}"
                    ),
                    "subscription": {
                        "resourceProviders": [
                            "Microsoft.OperationsManagement/solutions",
                            "Microsoft.OperationalInsights/workspaces/providers/alertRules",
                            "Microsoft.Insights/workbooks",
                        ]
                    },
                    "location": {
                        "metadata": {
                            "hidden": "Location is derived from the selected Log Analytics workspace."
                        },
                        "visible": False,
                    },
                    "resourceGroup": {
                        "allowExisting": True,
                    },
                },
            },
            "basics": [
                {
                    "name": "getLAWorkspace",
                    "type": "Microsoft.Solutions.ArmApiControl",
                    "toolTip": "Filters by Log Analytics workspaces that exist in the selected resource group.",
                    "condition": "[greater(length(resourceGroup().name),0)]",
                    "request": {
                        "method": "GET",
                        "path": "[concat(subscription().id,'/providers/Microsoft.OperationalInsights/workspaces?api-version=2020-08-01')]",
                    },
                },
                {
                    "name": "workspace",
                    "type": "Microsoft.Common.DropDown",
                    "label": "Workspace",
                    "placeholder": "Select a workspace",
                    "toolTip": "Select an existing Log Analytics workspace in this resource group with Microsoft Sentinel enabled.",
                    "constraints": {
                        "allowedValues": "[map(filter(basics('getLAWorkspace').value, (filter) => contains(toLower(filter.id), toLower(resourceGroup().name))), (item) => parse(concat('{\"label\":\"', item.name, '\",\"value\":\"', item.name, '\"}')))]",
                        "required": True,
                    },
                    "visible": True,
                },
            ],
            "steps": steps,
            "outputs": {
                "workspace-location": "[first(map(filter(basics('getLAWorkspace').value, (filter) => and(contains(toLower(filter.id), toLower(resourceGroup().name)),equals(filter.name,basics('workspace')))), (item) => item.location))]",
                "location": "[location()]",
                "workspace": "[basics('workspace')]",
            },
        },
    }


def render_json(obj: dict) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=False) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify committed Package/ files match the freshly generated V3 package.",
    )
    args = parser.parse_args(argv)

    solution, metadata = load_solution()
    outputs = {
        PACKAGE_DIR / "mainTemplate.json": render_json(build_main_template(solution, metadata)),
        PACKAGE_DIR / "createUiDefinition.json": render_json(build_create_ui_definition(solution)),
    }

    if args.check:
        mismatches = []
        for path, expected in outputs.items():
            if not path.exists():
                mismatches.append(f"Missing {path.relative_to(REPO_ROOT)}")
            elif path.read_text(encoding="utf-8") != expected:
                mismatches.append(
                    f"Out of date: {path.relative_to(REPO_ROOT)} (run python3 tools/sentinel/build_solution.py)"
                )
        if mismatches:
            for msg in mismatches:
                print(msg, file=sys.stderr)
            return 1
        print("Solutions/Bower/Package/ matches generated V3 output.")
        return 0

    PACKAGE_DIR.mkdir(parents=True, exist_ok=True)
    for path, content in outputs.items():
        path.write_text(content, encoding="utf-8")
        print(f"Wrote {path.relative_to(REPO_ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
