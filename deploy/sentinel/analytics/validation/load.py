#!/usr/bin/env python3
"""Upload a synthetic firewall-deny load to the Bower DCR stream, to measure rule query cost.

backfill  upload --rows events with event times spread evenly over the last --span-minutes,
          as fast as --workers allow, so every later rule run reads them in its look-back.
trickle   upload on-time events at --rate per second for --duration-minutes.

Addresses are IPv6 documentation addresses (RFC 3849) assigned round-robin, and the
command refuses a load that could put --threshold events of one address in one
--bucket-minutes event-time bucket, so one invocation never raises a detection. Pass the
deployed rule's firewallDenyThreshold and bucketMinutes. The guarantee covers one
invocation only: give loads whose event times can share a bucket disjoint address ranges
(--address-offset at least the previous offset plus its --addresses). Rows are gzip-compressed;
the token comes from the signed-in Azure CLI identity (use an isolated AZURE_CONFIG_DIR)
and is never printed. The summary is metadata only: counts, statuses and timings.
"""

import argparse
import concurrent.futures
import datetime
import email.utils
import gzip
import json
import math
import subprocess
import sys
import threading
import time
import urllib.error
import urllib.request
import uuid

# Refresh this long before the token expires. The Azure CLI hands back its cached token
# until less than five minutes are left, so a shorter margin never asks it again for the
# token it just returned.
TOKEN_MARGIN_SECONDS = 4 * 60


def stamp(value):
    return value.isoformat(timespec="microseconds").replace("+00:00", "Z")


def address(index, addresses, offset):
    slot = offset + index % addresses
    return f"2001:db8:{slot >> 16:x}:{slot & 0xFFFF:x}::1"


def row(prefix, index, at, addresses, offset, collector_id):
    return {"schemaVersion": "1.0.0", "eventId": f"{prefix}-{index:09d}", "timeGenerated": stamp(at),
            "eventCategory": "network-security", "eventType": "network_connection_denied",
            "eventAction": "network.connect", "eventResult": "denied", "eventOutcomeReason": "FirewallPolicyDeny",
            "application": {"name": "nftables-firewall", "environment": "load"},
            "source": {"ipAddress": address(index, addresses, offset)},
            "collector": {"id": collector_id, "version": "load-test", "sourceAdapter": "direct-logs-ingestion"}}


def per_address_bound(events_per_bucket, addresses):
    # Round-robin over contiguous indices; a bucket edge can split one cycle, so add one.
    return math.ceil(events_per_bucket / addresses) + 1


def trickle_plan(rate, batch):
    """Seconds between trickle requests and events per request, as the trickle loop sends them."""
    # One request every `tick` seconds keeps the rate without a request per event.
    tick = max(1.0, min(30.0, batch / max(rate, 0.001)))
    return tick, max(1, round(rate * tick))


def trickle_step(rate, tick, remaining):
    """Length of the next trickle step and its events: a full tick, or what is left of the run."""
    step = max(0.0, min(tick, remaining))
    return step, max(1, round(rate * step))


def chunks(count, batch):
    """Split one step's events into requests of at most `batch` rows."""
    return [min(batch, count - start) for start in range(0, count, batch)]


def events_per_bucket(args):
    """Most events one event-time bucket can receive from this load, as actually sent."""
    bucket_seconds = args.bucket_minutes * 60
    if args.mode == "backfill":
        # Evenly spaced event times: a bucket holds at most ceil(bucket / step) + 1 of them.
        return math.ceil(args.rows * args.bucket_minutes / args.span_minutes) + 1
    # Requests are at least `tick` apart and each sends `count` events with one event time,
    # so a bucket sees at most floor(bucket / tick) + 1 requests. A rate below one event per
    # request still sends one event per request, more than rate x bucket.
    tick, count = trickle_plan(args.rate, args.batch)
    return count * (math.floor(bucket_seconds / tick) + 1)


def retry_after(value, default):
    """Seconds to wait from a Retry-After header: delta-seconds or an HTTP date; else the default."""
    if not value:
        return default
    try:
        return max(0.0, float(value))
    except ValueError:
        pass
    try:
        when = email.utils.parsedate_to_datetime(value)
    except (TypeError, ValueError):
        return default
    if when is None:
        return default
    if when.tzinfo is None:
        when = when.replace(tzinfo=datetime.timezone.utc)
    return max(0.0, (when - datetime.datetime.now(datetime.timezone.utc)).total_seconds())


class Uploader:
    def __init__(self, endpoint, dcr):
        self.url = f"{endpoint.rstrip('/')}/dataCollectionRules/{dcr}/streams/Custom-BowerSecurity?api-version=2023-01-01"
        self.lock = threading.Lock()
        self.token, self.token_expires = None, 0.0
        self.stats = {"requests": 0, "rows": 0, "uncompressedBytes": 0, "compressedBytes": 0, "retries": 0,
                      "statuses": {}, "maxRequestSeconds": 0.0}

    def _token(self, force=False):
        with self.lock:
            if force or self.token is None or time.time() > self.token_expires - TOKEN_MARGIN_SECONDS:
                token = json.loads(subprocess.run(["az", "account", "get-access-token", "--resource", "https://monitor.azure.com",
                                                   "--query", "{token: accessToken, expires: expires_on}", "-o", "json"],
                                                  check=True, capture_output=True, text=True).stdout)
                self.token, self.token_expires = token["token"], float(token["expires"])
            return self.token

    def send(self, rows):
        body = json.dumps(rows, separators=(",", ":")).encode()
        packed = gzip.compress(body)
        refreshed = False
        for attempt in range(8):
            request = urllib.request.Request(self.url, packed, method="POST", headers={
                "Content-Type": "application/json", "Content-Encoding": "gzip",
                "Authorization": "Bearer " + self._token()})
            started = time.monotonic()
            try:
                with urllib.request.urlopen(request, timeout=60) as response:
                    status, wait = response.status, 0
            except urllib.error.HTTPError as error:
                status, wait = error.code, retry_after(error.headers.get("Retry-After"), 2 ** attempt)
            except (urllib.error.URLError, TimeoutError):
                status, wait = "network-error", 2 ** attempt
            with self.lock:
                self.stats["statuses"][str(status)] = self.stats["statuses"].get(str(status), 0) + 1
                self.stats["maxRequestSeconds"] = max(self.stats["maxRequestSeconds"], round(time.monotonic() - started, 3))
                if status in (200, 204):
                    self.stats["requests"] += 1
                    self.stats["rows"] += len(rows)
                    self.stats["uncompressedBytes"] += len(body)
                    self.stats["compressedBytes"] += len(packed)
                    return
                self.stats["retries"] += 1
            if status == 401 and not refreshed:
                # A token that expired early: fetch a new one once, then retry at once.
                refreshed, wait = True, 0
                self._token(force=True)
            elif status not in (429, 500, 502, 503, 504, "network-error"):
                raise SystemExit(f"upload refused with HTTP {status}")
            time.sleep(min(wait, 60))
        raise SystemExit("upload kept failing after retries")


def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("mode", choices=["backfill", "trickle"])
    parser.add_argument("--endpoint", required=True, help="DCE logs ingestion endpoint")
    parser.add_argument("--dcr", required=True, help="DCR immutable ID")
    parser.add_argument("--rows", type=int, default=0, help="events to upload (backfill)")
    parser.add_argument("--span-minutes", type=float, default=120, help="event times spread over this past span (backfill)")
    parser.add_argument("--rate", type=float, default=0, help="events per second (trickle)")
    parser.add_argument("--duration-minutes", type=float, default=0, help="how long to trickle")
    parser.add_argument("--addresses", type=int, default=8192)
    parser.add_argument("--address-offset", type=int, default=0, help="first address slot, to separate loads")
    parser.add_argument("--threshold", type=int, required=True,
                        help="the deployed firewall rule's firewallDenyThreshold (template default 20)")
    parser.add_argument("--bucket-minutes", type=float, required=True,
                        help="the deployed rules' bucketMinutes (template default 10)")
    parser.add_argument("--batch", type=int, default=2000, help="rows per request (keep under 1 MB uncompressed)")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--collector-id", default="load-direct")
    parser.add_argument("--summary", required=True, help="metadata-only JSON summary written here")
    args = parser.parse_args(argv)

    # Ranges as main.bicep allows them (threshold at least 2, bucket 1 to 60 minutes).
    problems = [message for failed, message in (
        (args.addresses < 1, "--addresses must be at least 1"),
        (args.address_offset < 0, "--address-offset must not be negative"),
        (args.threshold < 2, "--threshold must be at least 2 (the template minimum)"),
        (not 1 <= args.bucket_minutes <= 60, "--bucket-minutes must be 1 to 60 (the template range)"),
        (args.batch < 1, "--batch must be at least 1"),
        (args.workers < 1, "--workers must be at least 1"),
        (args.mode == "backfill" and args.rows < 1, "backfill needs --rows of at least 1"),
        (args.mode == "backfill" and args.span_minutes <= 0, "backfill needs a positive --span-minutes"),
        (args.mode == "trickle" and args.rate <= 0, "trickle needs a positive --rate"),
        (args.mode == "trickle" and args.duration_minutes <= 0, "trickle needs a positive --duration-minutes"),
    ) if failed]
    if problems:
        raise SystemExit("; ".join(problems))
    bound = per_address_bound(events_per_bucket(args), args.addresses)
    if bound >= args.threshold:
        raise SystemExit(f"up to {bound} events per address and bucket would reach the threshold {args.threshold}: "
                         "use more --addresses")

    # Open the summary before sending anything: the event id prefix is recorded only there.
    with open(args.summary, "w", encoding="utf-8") as output:
        summary = run(args, bound)
        output.write(json.dumps(summary, indent=1) + "\n")
    print(json.dumps({key: summary[key] for key in ("mode", "rows", "requests", "retries", "seconds", "statuses")}))


def run(args, bound):
    prefix = f"load-{args.mode}-{uuid.uuid4().hex[:8]}"
    uploader = Uploader(args.endpoint, args.dcr)
    started = datetime.datetime.now(datetime.timezone.utc)
    if args.mode == "backfill":
        first = started - datetime.timedelta(minutes=args.span_minutes)
        step = datetime.timedelta(minutes=args.span_minutes) / args.rows
        with concurrent.futures.ThreadPoolExecutor(args.workers) as pool:
            futures = [pool.submit(uploader.send, [row(prefix, i, first + step * i, args.addresses, args.address_offset,
                                                       args.collector_id) for i in range(lo, min(lo + args.batch, args.rows))])
                       for lo in range(0, args.rows, args.batch)]
            for future in futures:
                future.result()
    else:
        index, deadline = 0, time.monotonic() + args.duration_minutes * 60
        tick, _ = trickle_plan(args.rate, args.batch)
        while time.monotonic() < deadline:
            # The last step is cut to the time left, so the run ends at its deadline.
            step, count = trickle_step(args.rate, tick, deadline - time.monotonic())
            due = time.monotonic() + step
            at = datetime.datetime.now(datetime.timezone.utc)
            for size in chunks(count, args.batch):
                uploader.send([row(prefix, index + i, at, args.addresses, args.address_offset, args.collector_id)
                               for i in range(size)])
                index += size
            time.sleep(max(0.0, due - time.monotonic()))
    finished = datetime.datetime.now(datetime.timezone.utc)
    return {"mode": args.mode, "eventIdPrefix": prefix, "collectorId": args.collector_id,
            "startedAt": stamp(started), "finishedAt": stamp(finished),
            "seconds": round((finished - started).total_seconds(), 1), "addresses": args.addresses,
            "addressOffset": args.address_offset, "threshold": args.threshold, "bucketMinutes": args.bucket_minutes,
            "maxEventsPerAddressAndBucket": bound,
            "spanMinutes": args.span_minutes if args.mode == "backfill" else None,
            "ratePerSecond": args.rate if args.mode == "trickle" else None, **uploader.stats}


if __name__ == "__main__":
    main(sys.argv[1:])
