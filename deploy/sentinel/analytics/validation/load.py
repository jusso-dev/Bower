#!/usr/bin/env python3
"""Upload a synthetic firewall-deny load to the Bower DCR stream, to measure rule query cost.

backfill  upload --rows events with event times spread evenly over the last --span-minutes,
          as fast as --workers allow, so every later rule run reads them in its look-back.
trickle   upload on-time events at --rate per second for --duration-minutes.

Addresses are IPv6 documentation addresses (RFC 3849) assigned round-robin, and the
command refuses a load that could put --threshold events of one address in one
event-time bucket, so the load itself never raises a detection. Rows are gzip-compressed;
the token comes from the signed-in Azure CLI identity (use an isolated AZURE_CONFIG_DIR)
and is never printed. The summary is metadata only: counts, statuses and timings.
"""

import argparse
import concurrent.futures
import datetime
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

# Refresh this long before the token expires; the Azure CLI may hand back a cached token
# with only minutes left.
TOKEN_MARGIN_SECONDS = 10 * 60


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
                status, wait = error.code, float(error.headers.get("Retry-After") or 2 ** attempt)
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
    parser.add_argument("--threshold", type=int, default=20, help="firewall rule threshold the load must stay below")
    parser.add_argument("--bucket-minutes", type=float, default=10)
    parser.add_argument("--batch", type=int, default=2000, help="rows per request (keep under 1 MB uncompressed)")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--collector-id", default="load-direct")
    parser.add_argument("--summary", required=True, help="metadata-only JSON summary written here")
    args = parser.parse_args(argv)

    if args.mode == "backfill":
        events_per_bucket = args.rows * args.bucket_minutes / args.span_minutes
    else:
        events_per_bucket = args.rate * args.bucket_minutes * 60
    bound = per_address_bound(events_per_bucket, args.addresses)
    if bound >= args.threshold:
        raise SystemExit(f"up to {bound} events per address and bucket would reach the threshold {args.threshold}: "
                         "use more --addresses")

    prefix = f"load-{args.mode}-{uuid.uuid4().hex[:8]}"
    uploader = Uploader(args.endpoint, args.dcr)
    started = datetime.datetime.now(datetime.timezone.utc)
    if args.mode == "backfill":
        first = started - datetime.timedelta(minutes=args.span_minutes)
        step = datetime.timedelta(minutes=args.span_minutes) / max(args.rows, 1)
        with concurrent.futures.ThreadPoolExecutor(args.workers) as pool:
            futures = [pool.submit(uploader.send, [row(prefix, i, first + step * i, args.addresses, args.address_offset,
                                                       args.collector_id) for i in range(lo, min(lo + args.batch, args.rows))])
                       for lo in range(0, args.rows, args.batch)]
            for future in futures:
                future.result()
    else:
        index, deadline = 0, time.monotonic() + args.duration_minutes * 60
        # One request every `tick` seconds keeps the rate without a request per event.
        tick = max(1.0, min(30.0, args.batch / max(args.rate, 0.001)))
        while time.monotonic() < deadline:
            due = time.monotonic() + tick
            count = max(1, round(args.rate * tick))
            at = datetime.datetime.now(datetime.timezone.utc)
            uploader.send([row(prefix, index + i, at, args.addresses, args.address_offset, args.collector_id)
                           for i in range(count)])
            index += count
            time.sleep(max(0.0, due - time.monotonic()))
    finished = datetime.datetime.now(datetime.timezone.utc)
    summary = {"mode": args.mode, "eventIdPrefix": prefix, "collectorId": args.collector_id,
               "startedAt": stamp(started), "finishedAt": stamp(finished),
               "seconds": round((finished - started).total_seconds(), 1), "addresses": args.addresses,
               "addressOffset": args.address_offset, "maxEventsPerAddressAndBucket": bound,
               "spanMinutes": args.span_minutes if args.mode == "backfill" else None,
               "ratePerSecond": args.rate if args.mode == "trickle" else None, **uploader.stats}
    with open(args.summary, "w", encoding="utf-8") as output:
        output.write(json.dumps(summary, indent=1) + "\n")
    print(json.dumps({key: summary[key] for key in ("mode", "rows", "requests", "retries", "seconds", "statuses")}))


if __name__ == "__main__":
    main(sys.argv[1:])
