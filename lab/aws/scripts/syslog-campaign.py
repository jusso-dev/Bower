#!/usr/bin/env python3
"""Run syslog delivery-reliability scenarios against a lab created by syslog-lab.py.

Each scenario schedules generators and faults on the lab hosts at a common future time
(start time + offset), waits, then measures exact sequence-key sets at Bower queue
acceptance on each collector. Results are metadata-only JSON, one file per scenario;
an existing result is never overwritten (failed attempts are kept).
"""
import argparse
import importlib.util
import json
from pathlib import Path
import time

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("syslog_lab", HERE / "syslog-lab.py")
lab = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(lab)
SCRIPT = HERE / "syslog-host.sh"


def host(state, name, args, unit=None, timeout=1800):
    env = {"BOWER_ARGS": args}
    if unit:
        env["BOWER_UNIT"] = unit
    record = lab.send(state, name, SCRIPT, env, timeout)
    result = lab.wait(record)
    text = result["StandardOutputContent"]
    try:
        payload = json.loads(text[text.index("{"):text.rindex("}") + 1]) if "{" in text else {"output": text.strip()}
    except ValueError:
        payload = {"output": text.strip()[-2000:]}
    if result["Status"] != "Success":
        payload = {"status": result["Status"], "stderr": result["StandardErrorContent"][-2000:], **payload}
    return payload


def nft(track, number, count, offset=0):
    first = number * 20000 + offset
    return "nft:{}:{}:{}".format(track, first, count), first


def generate(sender, track, number, count, rate, offset=0, label="", at=0.0):
    first = number * 20000 + offset
    return {"at": at, "host": sender, "unit": label,
            "args": "generate --kind nft --track {} --first {} --count {} --rate {} --label {}".format(track, first, count, rate, label)}


def lines(sender, letter, number, file, first, count, rate, label, at=0.0):
    return {"at": at, "host": sender, "unit": label,
            "args": "generate --kind file --file {} --sender {} --scenario {} --first {} --count {} --rate {} --label {}".format(
                file, letter, number, first, count, rate, label)}


def scenarios(state):
    """Scenario catalogue. Track A (CollectorA) carries faults; track B (CollectorB) idle gaps."""
    peers = state["outputs"]["SenderRIp"] + "," + state["outputs"]["SenderGIp"]
    a, b = "a13,a12", "b13i,b13n,b12i"
    catalogue = {}

    def add(name, number, steps, duration, measure, before=(), after=(), settle=120):
        catalogue[name] = {"name": name, "number": number, "steps": steps, "duration": duration,
                           "measure": measure, "before": list(before), "after": list(after), "settle": settle}

    # Baseline reproduction (pilot build, listener idle timeout 60 s, pilot sender profile).
    add("base-idle-close", 1, [generate("SenderR", "A", 1, 50, 10, 0, "base-idle-1", 0),
                               generate("SenderR", "A", 1, 50, 100, 50, "base-idle-2", 80),
                               generate("SenderR", "A", 1, 50, 100, 100, "base-idle-3", 160),
                               generate("SenderR", "A", 1, 50, 100, 150, "base-idle-4", 240)],
        260, [("CollectorA", a, "nft:A:20000:200")], settle=60)
    rsyslog = "configure-rsyslog --a {} --b {} --cert sender-r".format(state["outputs"]["CollectorAIp"], state["outputs"]["CollectorBIp"])
    pilot = rsyslog + " --profile pilot --only a13,a12"
    add("base-rebind1", 2, [generate("SenderR", "A", 2, 6000, 100, 0, "base-rebind1", 0)], 70,
        [("CollectorA", a, "nft:A:40000:6000")], before=[("SenderR", pilot + " --rebind 1")],
        after=[("SenderR", pilot + " --rebind 0")], settle=120)
    add("base-restart", 3, [generate("SenderR", "A", 3, 6000, 100, 0, "base-restart", 0),
                            {"at": 20, "host": "CollectorA", "unit": "f-base-restart", "args": "fault --action restart"}],
        70, [("CollectorA", a, "nft:A:60000:6000")])
    add("base-sigkill", 4, [generate("SenderR", "A", 4, 6000, 100, 0, "base-sigkill", 0),
                            {"at": 20, "host": "CollectorA", "unit": "f-base-kill", "args": "fault --action kill"}],
        70, [("CollectorA", a, "nft:A:80000:6000")])
    # Fixed build, recommended profile: faults on track A.
    add("a-steady", 10, [generate("SenderR", "A", 10, 600, 10, 0, "a-steady", 0)], 65, [("CollectorA", a, "nft:A:200000:600")], settle=60)
    add("a-restart", 11, [generate("SenderR", "A", 11, 6000, 100, 0, "a-restart", 0),
                          {"at": 20, "host": "CollectorA", "unit": "f-restart", "args": "fault --action restart"}],
        70, [("CollectorA", a, "nft:A:220000:6000")])
    add("a-sigkill", 12, [generate("SenderR", "A", 12, 6000, 100, 0, "a-sigkill", 0),
                          {"at": 20, "host": "CollectorA", "unit": "f-kill", "args": "fault --action kill"}],
        70, [("CollectorA", a, "nft:A:240000:6000")])
    add("a-blackhole", 13, [generate("SenderR", "A", 13, 1800, 10, 0, "a-blackhole", 0),
                            {"at": 30, "host": "CollectorA", "unit": "f-blackhole",
                             "args": "fault --action blackhole --duration 120 --peers " + peers}],
        190, [("CollectorA", a, "nft:A:260000:1800")], settle=300)
    add("a-reset", 14, [generate("SenderR", "A", 14, 1200, 10, 0, "a-reset", 0),
                        {"at": 30, "host": "CollectorA", "unit": "f-reset",
                         "args": "fault --action reset --duration 10 --peers " + peers}],
        130, [("CollectorA", a, "nft:A:280000:1200")], settle=180)
    add("a-collector-reboot", 15, [generate("SenderR", "A", 15, 3000, 10, 0, "a-reboot", 0),
                                   {"at": 30, "host": "CollectorA", "unit": "f-reboot", "args": "fault --action reboot"}],
        310, [("CollectorA", a, "nft:A:300000:3000")], settle=300)
    add("a-rotate-create", 16, [lines("SenderR", "r", 16, "create", 0, 12000, 100, "a-rot-create", 0),
                                {"at": 15, "host": "SenderR", "unit": "rot-create", "args": "rotate --mode create --times 4 --interval 25"}],
        125, [("CollectorA", a, "file:r:16:0:12000")])
    add("a-rotate-copytruncate", 17, [lines("SenderR", "r", 17, "copytruncate", 0, 12000, 100, "a-rot-copy", 0),
                                      {"at": 15, "host": "SenderR", "unit": "rot-copy",
                                       "args": "rotate --mode copytruncate --times 4 --interval 25"}],
        125, [("CollectorA", a, "file:r:17:0:12000")])
    add("a-sender-stop-start", 18, [generate("SenderR", "A", 18, 1800, 10, 0, "a-sender-stop", 0),
                                    {"at": 30, "host": "SenderR", "unit": "f-sender-stop",
                                     "args": "fault --action stop-start --unit rsyslog --duration 60"}],
        190, [("CollectorA", a, "nft:A:360000:1800")])
    add("a-journal-rotate", 19, [generate("SenderR", "A", 19, 6000, 100, 0, "a-journal-rotate", 0),
                                 {"at": 5, "host": "SenderR", "unit": "f-journal-rotate",
                                  "args": "fault --action journal-rotate --duration 50 --interval 5"}],
        70, [("CollectorA", a, "nft:A:380000:6000")])
    # Idle track B: gaps of 5, 30 and 65 minutes (longer than b13i/b12i's 3600 s idle timeout),
    # then a 100/s burst. b13n never closes idle connections; b12i's sender pins TLS 1.2.
    add("b-idle-gaps", 30, [generate("SenderR", "B", 30, 100, 10, 0, "b-idle-p0", 0),
                            generate("SenderR", "B", 30, 100, 100, 100, "b-idle-p1", 310),
                            generate("SenderR", "B", 30, 100, 100, 200, "b-idle-p2", 2115),
                            generate("SenderR", "B", 30, 6000, 100, 300, "b-idle-p3", 6020)],
        6085, [("CollectorB", b, "nft:B:600000:100", "before-gaps"),
               ("CollectorB", b, "nft:B:600100:100", "after-5min"),
               ("CollectorB", b, "nft:B:600200:100", "after-30min"),
               ("CollectorB", b, "nft:B:600300:6000", "burst-after-65min")], settle=1200)
    add("a-restart-sg-strict", 20, [generate("SenderR", "A", 20, 6000, 100, 0, "a-restart-strict", 0),
                                    {"at": 20, "host": "CollectorA", "unit": "f-restart-strict", "args": "fault --action restart"}],
        70, [("CollectorA", a, "nft:A:400000:6000")], settle=300)
    # Restart, then sender silence: the closed flow ages out of security-group tracking before
    # the sender writes again (the baseline idle-close stall). Run with strict and open egress.
    for name, number in (("a-restart-quiet-sg-strict", 21), ("a-restart-quiet-sg-open", 22)):
        add(name, number, [generate("SenderR", "A", number, 100, 10, 0, name + "-1", 0),
                           {"at": 15, "host": "CollectorA", "unit": "f-" + name, "args": "fault --action restart"},
                           generate("SenderR", "A", number, 1000, 100, 100, name + "-2", 200)],
            215, [("CollectorA", a, "nft:A:{}:1100".format(number * 20000))], settle=300)
    add("a-journal-rotate-fixed", 23, [generate("SenderR", "A", 23, 6000, 100, 0, "a-journal-rotate-fixed", 0),
                                       {"at": 5, "host": "SenderR", "unit": "f-journal-rotate-fixed",
                                        "args": "fault --action journal-rotate --duration 50 --interval 5"}],
        70, [("CollectorA", a, "nft:A:460000:6000")])
    # Sender reboot with messages queued: the collector is stopped, so rsyslog queues
    # (disk-assisted, saveOnShutdown) and must deliver them after its host reboots.
    add("a-sender-reboot", 24, [{"at": 0, "host": "CollectorA", "unit": "f-collector-down",
                                 "args": "fault --action stop-start --duration 240"},
                                generate("SenderR", "A", 24, 600, 10, 0, "a-sender-reboot", 5),
                                {"at": 80, "host": "SenderR", "unit": "f-sender-reboot", "args": "fault --action reboot"}],
        330, [("CollectorA", a, "nft:A:480000:600")], settle=300)
    # Reruns with the generator reopening the file per line (the first create-mode run kept
    # its descriptor and wrote into the renamed file; that failed attempt is preserved).
    # SenderG (syslog-ng) rotates and writes its own file at the same time.
    for name, number, mode in (("a-rotate-create-2", 27, "create"), ("a-rotate-copytruncate-2", 28, "copytruncate")):
        add(name, number, [lines("SenderR", "r", number, mode, 0, 12000, 100, name, 0),
                           lines("SenderG", "g", number, mode, 0, 12000, 100, name + "-g", 0),
                           {"at": 15, "host": "SenderR", "unit": "rot-" + name,
                            "args": "rotate --mode {} --times 4 --interval 25".format(mode)},
                           {"at": 15, "host": "SenderG", "unit": "rot-" + name + "-g",
                            "args": "rotate --mode {} --times 4 --interval 25".format(mode)}],
            125, [("CollectorA", a, "file:r:{0}:0:12000+file:g:{0}:0:12000".format(number))])
    # Both senders through the same collector faults; rsyslog sends kernel denials,
    # syslog-ng sends file lines.
    def both(name, number, fault, settle=300, rate=100):
        # Each event goes to two listeners, so two senders at 50/s give the collector 200
        # frames/s, inside its measured intake capacity; 100/s each (400 frames/s) exceeds it.
        count = rate * 60
        add(name, number, [generate("SenderR", "A", number, count, rate, 0, name, 0),
                           lines("SenderG", "g", number, "create", 0, count, rate, name + "-g", 0), fault],
            70, [("CollectorA", a, "nft:A:{0}:{2}+file:g:{1}:0:{2}".format(number * 20000, number, count))], settle=settle)
    both("ag-restart-tickets-2", 35, {"at": 20, "host": "CollectorA", "unit": "f-ag-restart-t2", "args": "fault --action restart"}, settle=120)
    both("ag-restart-tickets", 32, {"at": 20, "host": "CollectorA", "unit": "f-ag-restart-t", "args": "fault --action restart"}, settle=120)
    both("ag-sigkill-notickets", 26, {"at": 20, "host": "CollectorA", "unit": "f-ag-kill-nt", "args": "fault --action kill"}, rate=50)
    # Fixed build with the 20 s stop drain (bower 0.1.0~dev with StopTimeout).
    both("ag-restart-notickets", 25, {"at": 20, "host": "CollectorA", "unit": "f-ag-restart-nt", "args": "fault --action restart"}, rate=50)
    both("ag-restart-tickets-50", 36, {"at": 20, "host": "CollectorA", "unit": "f-ag-restart-t50", "args": "fault --action restart"}, rate=50)
    both("ag-restart-notickets-100", 37, {"at": 20, "host": "CollectorA", "unit": "f-ag-restart-nt100", "args": "fault --action restart"})
    # syslog-ng after its own connections to CollectorB sat idle for over an hour.
    add("bg-idle-burst", 34, [lines("SenderG", "g", 34, "idle", 0, 6000, 100, "bg-idle-burst", 0)],
        65, [("CollectorB", b, "file:g:34:0:6000")], settle=600)
    add("g-sender-restart", 33, [lines("SenderG", "g", 33, "create", 0, 1800, 10, "g-sender-restart", 0),
                                 {"at": 30, "host": "SenderG", "unit": "f-g-restart",
                                  "args": "fault --action docker-restart --duration 60"}],
        190, [("CollectorA", a, "file:g:33:0:1800")])
    # Collector up but not reading (frozen process: TCP backpressure, as when Bower's queue is
    # full) versus down, for five minutes at 100/s, with three rsyslog queue profiles.
    def outage(name, number, action, queue):
        configure = rsyslog + " --profile recommended --queue " + queue
        first = 1000000 + (number - 40) * 50000   # non-overlapping 42,000-event blocks
        add(name, number, [generate("SenderR", "A", number, 42000, 100, first - number * 20000, name, 0),
                           {"at": 60, "host": "CollectorA", "unit": "f-" + name,
                            "args": "fault --action {} --duration 300".format(action)}],
            425, [("CollectorA", a, "nft:A:{}:42000".format(first))],
            before=[("SenderR", configure)], settle=900)
    outage("a-stall-recommended", 40, "stall", "recommended")
    outage("a-down-recommended", 41, "stop-start", "recommended")
    outage("a-stall-pilot-queue", 42, "stall", "pilot")
    outage("a-down-pilot-queue", 43, "stop-start", "pilot")
    outage("a-stall-small-queue", 44, "stall", "small")
    return catalogue


def run(state, scenario, output, lead):
    target = output / (scenario["name"] + ".json")
    if target.exists():
        raise SystemExit(target.name + " exists; keep it and use a new scenario name for a rerun")
    record = {"scenario": scenario["name"], "runId": state["runId"], "before": [], "steps": [], "after": []}
    for name, args in scenario["before"]:
        record["before"].append({"host": name, "args": args, "result": host(state, name, args)})
    start = time.time() + lead
    record["startAt"] = start
    for step in scenario["steps"]:
        args = step["args"] + " --at {:.3f}".format(start + step["at"])
        record["steps"].append({"host": step["host"], "offset": step["at"], "args": step["args"],
                                "submitted": host(state, step["host"], args, unit=step.get("unit"))})
    time.sleep(max(0, start + scenario["duration"] - time.time()))
    for step in scenario["steps"]:
        if step["args"].startswith(("generate", "fault", "rotate")):
            label = step["unit"]
            step_result = host(state, step["host"], "result --label generate-" + label) if step["args"].startswith("generate") else None
            record["steps"].append({"result": label, "value": step_result})
    record["measurements"] = {}
    for collector, listeners, blocks, *label in scenario["measure"]:
        key = collector + ("-" + label[0] if label else "")
        record["measurements"][key] = host(state, collector, "measure --scenario {} --listeners {} --blocks {} --settle {}".format(
            scenario["name"] + ("-" + label[0] if label else ""), listeners, blocks, scenario["settle"]), timeout=scenario["settle"] + 600)
        record["measurements"][key + "-snapshot"] = host(state, collector, "snapshot")
    record["measurements"]["SenderR"] = host(state, "SenderR", "sender-snapshot --since @{:.0f}".format(start - 5))
    if any(step["host"] == "SenderG" for step in scenario["steps"]):
        record["measurements"]["SenderG"] = host(state, "SenderG", "syslogng-snapshot --since {:.0f}".format(start - 5))
    for name, args in scenario["after"]:
        record["after"].append({"host": name, "args": args, "result": host(state, name, args)})
    # A generator that did not run (for example a late SSM delivery refused as a stale
    # schedule) makes the scenario invalid, never a delivery result.
    missing = [x["result"] for x in record["steps"] if "value" in x and (x["value"] or {}).get("missing")]
    if missing:
        record["invalid"] = "generator did not run: " + ", ".join(missing)
    record["passed"] = not missing and all(m.get("passed") for k, m in record["measurements"].items() if k.startswith("Collector") and "snapshot" not in k)
    output.mkdir(parents=True, exist_ok=True)
    target.write_text(json.dumps(record, indent=1, sort_keys=True) + "\n")
    summary = {k: {l: {f: v[f] for f in ("expected", "accepted", "missing")} for l, v in m["listeners"].items()}
               for k, m in record["measurements"].items() if isinstance(m, dict) and "listeners" in m}
    print(json.dumps({"scenario": scenario["name"], "passed": record["passed"], "summary": summary}, indent=1))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("scenario", nargs="+")
    parser.add_argument("--state", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--lead", type=int, default=60)
    args = parser.parse_args()
    lab.verify_account()
    state = lab.load_state(args.state)
    catalogue = scenarios(state)
    for name in args.scenario:
        run(state, catalogue[name], args.output, args.lead)


if __name__ == "__main__":
    main()
