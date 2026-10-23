#!/usr/bin/env python3
"""Create non-secret, deterministic deployment inputs. Never calls Azure."""
import argparse
import hashlib
import json
from pathlib import Path
import re
import uuid


def create_plan(workspace, location, prefix, principal=None, managed_identity=False):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{2,62}", workspace):
        raise ValueError("Workspace name must contain 3-63 letters, digits or hyphens.")
    if not re.fullmatch(r"[a-z][a-z0-9]{1,39}", location):
        raise ValueError("Use an Azure region identifier, such as australiaeast.")
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9-]{2,39}", prefix):
        raise ValueError("Name prefix must contain 3-40 letters, digits or hyphens.")
    if bool(principal) == managed_identity:
        raise ValueError("Select exactly one existing principal or new managed identity.")
    if principal:
        principal = str(uuid.UUID(principal))
        if uuid.UUID(principal).int == 0:
            raise ValueError("Principal object ID must not be the zero GUID.")
    parameters = {
        "$schema": "https://schema.management.azure.com/schemas/2019-04-01/deploymentParameters.json#",
        "contentVersion": "1.0.0.0",
        "parameters": {key: {"value": value} for key, value in {
            "workspaceName": workspace, "location": location, "namePrefix": prefix,
            "ingestPrincipalObjectId": principal or "", "createIngestIdentity": managed_identity,
        }.items()},
    }
    template = Path(__file__).resolve().parents[1] / "bicep" / "main.bicep"
    encoded = json.dumps(parameters, indent=2, sort_keys=True) + "\n"
    template_hash = hashlib.sha256(template.read_bytes()).hexdigest()
    parameters_hash = hashlib.sha256(encoded.encode()).hexdigest()
    plan = {
        "mode": "plan-only", "template": "deploy/bicep/main.bicep",
        "templateSha256": template_hash, "parametersSha256": parameters_hash,
        "planSha256": hashlib.sha256((template_hash + ":" + parameters_hash).encode()).hexdigest(),
        "ingestionRole": "Monitoring Metrics Publisher", "ingestionScope": "exact DCR",
        "credentialsCreated": False, "azureMutationsPerformed": False,
        "remainingChecks": ["Authorise and review Azure what-if in intended tenant/subscription.",
                            "Apply reviewed plan and attach identity to collector compute.",
                            "Use separate reader identity to query the canary in intended workspace/table.",
                            "Verify required sanitised fields; upload acceptance is not destination proof."],
    }
    return encoded, json.dumps(plan, indent=2, sort_keys=True) + "\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace-name", required=True)
    parser.add_argument("--location", default="australiaeast")
    parser.add_argument("--name-prefix", default="bower")
    identity = parser.add_mutually_exclusive_group(required=True)
    identity.add_argument("--principal-object-id")
    identity.add_argument("--create-managed-identity", action="store_true")
    parser.add_argument("--out", required=True, type=Path)
    args = parser.parse_args()
    try:
        parameters, plan = create_plan(args.workspace_name, args.location, args.name_prefix,
                                       args.principal_object_id, args.create_managed_identity)
    except ValueError as error:
        parser.error(str(error))
    args.out.mkdir(parents=True, exist_ok=True)
    # Refuse overwriting evidence from an earlier review.
    paths = [args.out / "ingestion.parameters.json", args.out / "ingestion.plan.json"]
    if any(path.exists() for path in paths):
        parser.error("Output plan already exists; select a new output directory.")
    for path, content in zip(paths, [parameters, plan]):
        with path.open("x") as stream:
            stream.write(content)
    print("Plan written. No credentials created; no Azure calls made.")


if __name__ == "__main__":
    main()
