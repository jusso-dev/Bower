#!/usr/bin/env python3
"""Plan the existing syslog scenarios for one collector and one separate sender.

This command performs no AWS calls and executes no scenario. It prints reviewed SSM
argument arrays for monitoring/run.py. The caller must provision/configure the
optional Sender first and retain each command's metadata-only result. The source
tools are supplied explicitly until the syslog-reliability branch is integrated.
"""

import argparse
import copy
import hashlib
import importlib.util
import ipaddress
import json
import math
import re
from pathlib import Path
import shlex
import sys
import time

HERE = Path(__file__).resolve().parent
SCENARIOS = ("a-steady", "a-burst", "a-restart", "a-sigkill", "a-blackhole", "a-reset",
             "a-collector-reboot", "a-sender-stop-start", "a-sender-reboot", "b-idle-gaps",
             "a-destination-outage")
ROLES = {"CollectorA": ("Linux", "CollectorA"), "CollectorB": ("Linux", "CollectorA"),
         "SenderR": ("Sender", "SenderR")}
# The native Track A rule logs only UDP destination ports 4400..4449.
# Each port encodes 40,000 source-port identities; Track B starts at 4450.
# Legal UDP ports outside that rule do not produce Track A firewall evidence.
SEQUENCE_LIMIT = 40000 * 50
MAX_BLOCK_COUNT = 200000


def parse_sequence_offset(value):
    if not re.fullmatch(r"[0-9]+", value):
        raise argparse.ArgumentTypeError("Sequence offset must be a nonnegative decimal integer")
    offset = int(value)
    if not 0 <= offset < SEQUENCE_LIMIT:
        raise argparse.ArgumentTypeError("Sequence offset exceeds the Track A firewall rule identity space")
    return offset


def shifted_first(first, count, offset):
    if (type(offset) is not int or not 0 <= offset < SEQUENCE_LIMIT
            or type(first) is not int or type(count) is not int or first < 0
            or not 1 <= count <= MAX_BLOCK_COUNT or first + offset + count > SEQUENCE_LIMIT):
        raise ValueError("Shifted nftables range exceeds Track A ports 4400..4449 or event count")
    return first + offset


def shifted_blocks(blocks, offset):
    shifted = []
    for block in blocks.split("+"):
        match = re.fullmatch(r"nft:[AB]:([0-9]+):([0-9]+)", block)
        if not match:
            raise ValueError("Only bounded nftables measurement blocks are supported")
        first, count = map(int, match.groups())
        shifted.append("nft:A:{}:{}".format(shifted_first(first, count, offset), count))
    return shifted


def load_catalogue(source, collector_ip, sender_ip):
    path = source / "syslog-campaign.py"
    spec = importlib.util.spec_from_file_location("bower_syslog_campaign", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    catalogue = module.scenarios({"outputs": {"CollectorAIp": collector_ip, "CollectorBIp": collector_ip,
                                              "SenderRIp": sender_ip, "SenderGIp": sender_ip}})
    # The existing campaign uses bursts during faults; add a clean burst with a
    # distinct port-derived identity range using the same source generator.
    catalogue["a-burst"] = {"name": "a-burst", "number": 40, "duration": 65, "settle": 120,
        "steps": [module.generate("SenderR", "A", 40, 6000, 100, label="a-burst")],
        "measure": [("CollectorA", "a13", "nft:A:800000:6000")], "before": [], "after": []}
    # The parent/operator must separately install and prove the ingestion-only
    # egress fault. Never reinterpret the campaign's 120s syslog blackhole as
    # a 1h destination outage, or block SSM/syslog traffic with a broad rule.
    catalogue["a-destination-outage"] = {"name": "a-destination-outage", "number": 50,
        "duration": 3605, "settle": 1800,
        "steps": [module.generate("SenderR", "A", 50, 36000, 10, label="a-destination-outage")],
        "measure": [("CollectorA", "a13", "nft:A:1000000:36000")], "before": [], "after": []}
    return catalogue


def plan(catalogue, name, source, state, collector_ip, sender_ip, start_epoch, sequence_offset=0):
    if type(sequence_offset) is not int or not 0 <= sequence_offset < SEQUENCE_LIMIT:
        raise ValueError("Sequence offset must be a bounded nonnegative integer")
    scenario = copy.deepcopy(catalogue[name])
    if scenario["before"] or scenario["after"]:
        raise ValueError("This adapter does not silently change sender or collector configuration")

    def command(host, arguments, unit=None, timeout=900):
        if host not in ROLES:
            raise ValueError("Scenario requires a host outside this topology")
        target, legacy_role = ROLES[host]
        argv = [sys.executable, str(HERE / "run.py"), target, str(source / "syslog-host.sh"),
                "--state", str(state), "--timeout", str(timeout),
                "--env", "BOWER_LAB_HOST=" + legacy_role, "--env", "BOWER_ARGS=" + arguments]
        if unit:
            argv.extend(["--env", "BOWER_UNIT=" + unit])
        return argv

    steps = []
    collect = []
    generations = []
    for step in scenario["steps"]:
        if step["host"] not in ROLES:
            raise ValueError("Scenario requires a host outside this topology")
        arguments = shlex.split(step["args"])
        if "--track" in arguments:
            arguments[arguments.index("--track") + 1] = "A"
        if "--peers" in arguments:
            arguments[arguments.index("--peers") + 1] = sender_ip
        if arguments[0] == "generate":
            if arguments.count("--first") != 1 or arguments.count("--count") != 1:
                raise ValueError("Generator range must have exactly one first/count pair")
            first = int(arguments[arguments.index("--first") + 1])
            count = int(arguments[arguments.index("--count") + 1])
            arguments[arguments.index("--first") + 1] = str(shifted_first(first, count, sequence_offset))
        scheduled = arguments + ["--at", format(start_epoch + step["at"], ".3f")]
        steps.append({"offsetSeconds": step["at"], "host": ROLES[step["host"]][0],
                      "command": command(step["host"], shlex.join(scheduled), step["unit"])})
        if arguments[0] == "generate":
            options = dict(zip(arguments[1::2], arguments[2::2]))
            if options.get("--kind") != "nft" or options.get("--track") != "A":
                raise ValueError("This qualification adapter supports only the scoped nftables source")
            generations.append({"kind": "nft", "track": "A", "first": int(options["--first"]),
                                "count": int(options["--count"]), "rate": float(options["--rate"]),
                                "label": options["--label"], "startEpoch": start_epoch + step["at"]})
            collect.append({"kind": "native-generator-result", "command": command(
                step["host"], "result --label generate-" + step["unit"])})
    expected_blocks = []
    for host, _listeners, blocks, *label in scenario["measure"]:
        shifted = shifted_blocks(blocks, sequence_offset)
        blocks = "+".join(shifted)
        expected_blocks.extend(shifted)
        measurement = name + ("-" + label[0] if label else "")
        collect.append({"kind": "queue-acceptance-only", "command": command(host,
            "measure --scenario {} --listeners a13 --blocks {} --settle {}".format(
                measurement, blocks, scenario["settle"]), timeout=scenario["settle"] + 600)})
    collect.extend([
        {"kind": "collector-snapshot", "command": command("CollectorA", "snapshot")},
        {"kind": "sender-snapshot", "command": command("SenderR", "sender-snapshot --since {}m".format(
            int(scenario["duration"] / 60) + 10))}])
    result = {"schemaVersion": 1, "scenario": name, "mode": "plan-only", "startEpoch": start_epoch,
            "sequenceOffset": sequence_offset,
            "collectNotBeforeEpoch": start_epoch + scenario["duration"],
            "steps": steps, "collect": collect, "expectedBlocks": expected_blocks, "generations": generations,
            "listener": "a13", "collectorIp": collector_ip, "senderIp": sender_ip,
            "sentinelQualified": False,
            "destinationRequirement": "Independently query the exact expected EventId set in Sentinel; local delivered_at is not proof.",
            "prerequisites": [
                "EnableSyslogSender=true and exact run ownership checked by monitoring/run.py.",
                "Reviewed syslog-host.py installed on Linux and Sender from their SHA-256-pinned qualification setup manifests.",
                "Linux collector listens on TCP 6514 with mutual TLS, listener a13, idleTimeoutSeconds=0, and the signed syslog-reliability pack.",
                "Use BOWER_QUEUE_PATH=/var/lib/bower/queue.db, the path inspected by the existing queue measurement helper.",
                "Sender has the nftables fixture and rsyslog recommended profile forwarding only a13; qualify the actual TLS version/ticket configuration.",
                "Keep the final Sentinel destination configuration; do not invoke the old configure-collector command, which selects ama-spool.",
                "No other scenario runs concurrently; idle-gaps must remain free of unrelated events on this listener.",
                "Retention must preserve all scoped queue identities until collection; preserve earlier evidence and use a disjoint sequence offset for a new candidate.",
            ]}
    if name == "a-destination-outage":
        result["externalFaultRequirement"] = {
            "implementedByThisPlan": False,
            "target": "Collector Bower service UID outbound TCP443 (IPv4/IPv6): ingestion and token refresh; preserve SSM and inbound syslog",
            "blockBeforeEpoch": start_epoch, "restoreNotBeforeEpoch": start_epoch + 3600,
            "minimumVerifiedDurationSeconds": 3600,
            "evidenceRequired": ["exact Bower service UID, scoped nftables rule hash and unchanged host boot ID",
                "independent timed restoration guard installed before blocking",
                "block activation and restoration timestamps; no Sentinel ingress during block",
                "queue retained all 36000 identities; peak depth/bytes and no drops",
                "post-restoration queue drain and independent Sentinel identity reconciliation"],
        }
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", choices=SCENARIOS)
    parser.add_argument("--source", type=Path, required=True, help="Reviewed directory containing the #165 syslog scripts")
    parser.add_argument("--state", type=Path, required=True, help="Public monitoring stack state used to bind host addresses and run identity")
    parser.add_argument("--collector-ip", required=True)
    parser.add_argument("--sender-ip", required=True)
    parser.add_argument("--start-epoch", type=float, required=True, help="Common future UTC epoch; allow at least 120 seconds to dispatch")
    parser.add_argument("--sequence-offset", type=parse_sequence_offset, default=0,
                        help="Add this nonnegative offset to every generator/measurement range within Track A ports 4400..4449 (default: 0)")
    args = parser.parse_args()
    if not math.isfinite(args.start_epoch) or args.start_epoch < time.time() + 120:
        parser.error("The common start must be finite and at least 120 seconds in the future")
    if args.collector_ip == args.sender_ip:
        parser.error("Sender and collector must be separate hosts")
    private_networks = [ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    for value in (args.collector_ip, args.sender_ip):
        address = ipaddress.ip_address(value)
        if address.version != 4 or not any(address in network for network in private_networks):
            parser.error("The isolated lab requires private IPv4 host addresses")
    source = args.source.resolve()
    state_path = args.state.resolve()
    if state_path.stat().st_size > 65536:
        parser.error("Monitoring state is oversized")
    state = json.loads(state_path.read_text())
    run_id = state.get("runId", "")
    if not re.fullmatch(r"bower-ws6-\d{8}-\d{6}", run_id):
        parser.error("Invalid monitoring run ID")
    if state.get("outputs", {}).get("LinuxIp") != args.collector_ip or state.get("outputs", {}).get("SenderIp") != args.sender_ip:
        parser.error("Plan addresses must match the owned monitoring state")
    try:
        result = plan(load_catalogue(source, args.collector_ip, args.sender_ip), args.scenario,
                      source, state_path, args.collector_ip, args.sender_ip, args.start_epoch, args.sequence_offset)
    except ValueError as error:
        parser.error(str(error))
    result["runId"] = run_id
    result["collectorId"] = run_id + "-linux"
    result["sourceSha256"] = {name: hashlib.sha256((source / name).read_bytes()).hexdigest()
                              for name in ("syslog-campaign.py", "syslog-host.py", "syslog-host.sh", "syslog-lab.py")}
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    main()
