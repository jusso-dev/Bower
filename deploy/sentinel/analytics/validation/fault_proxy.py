#!/usr/bin/env python3
"""Loopback HTTPS CONNECT proxy that injects Logs Ingestion delivery faults.

Point a test collector at it with HTTPS_PROXY=http://127.0.0.1:<port>. TLS stays end
to end between the collector and Azure; the proxy only sees tunnel byte counts and
never logs payloads, headers or credentials.

Modes (set with GET http://127.0.0.1:<control>/mode/<name>):
  pass                   forward everything.
  drop-next              on the next established ingestion tunnel that has sent at
                         least --request-bytes since arming (an upload with its
                         bearer token and body), discard
                         the response (the upload reached Azure; the acknowledgement
                         never reaches Bower), then return to pass. The tunnel stays
                         open, so the collector waits for its own delivery deadline.
  drop-next-then-outage  as drop-next, then enter outage straight away.
  outage                 refuse new tunnels and close existing ones, like an
                         outbound firewall block. Ambiguous tunnels stay hung.
Synthetic test traffic only. Standard library only.
"""

import argparse
import asyncio
import datetime
import itertools
import json
import sys

MODES = ("pass", "drop-next", "drop-next-then-outage", "outage")


class Proxy:
    def __init__(self, suffix, request_bytes, log_path):
        self.mode = "pass"
        self.suffix = suffix
        self.request_bytes = request_bytes
        self.log = open(log_path, "a", encoding="utf-8")
        self.ids = itertools.count(1)
        self.tunnels = {}
        self.poisoned = 0

    def record(self, event, **fields):
        fields.update(at=datetime.datetime.now(datetime.timezone.utc).isoformat(), event=event, mode=self.mode)
        self.log.write(json.dumps(fields, sort_keys=True) + "\n")
        self.log.flush()

    def set_mode(self, mode):
        previous, self.mode = self.mode, mode
        self.record("mode", previous=previous)
        if mode.startswith("drop-next"):
            # Arming: only requests sent from now on can be dropped.
            for tunnel in self.tunnels.values():
                if tunnel["baseline"] is not None:
                    tunnel["baseline"] = tunnel["up"]
        if mode == "outage":
            for tunnel in list(self.tunnels.values()):
                if not tunnel["poisoned"]:
                    tunnel["close"]()

    async def handle(self, reader, writer):
        number = next(self.ids)
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), 30)
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
            writer.close()
            return
        parts = head.split(b"\r\n", 1)[0].decode("latin-1").split()
        if len(parts) != 3 or parts[0] != "CONNECT" or ":" not in parts[1]:
            writer.write(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n")
            writer.close()
            return
        host, port = parts[1].rsplit(":", 1)
        if self.mode == "outage":
            self.record("refused", tunnel=number, host=host)
            writer.write(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
            writer.close()
            return
        try:
            upstream_reader, upstream_writer = await asyncio.wait_for(asyncio.open_connection(host, int(port)), 30)
        except (OSError, asyncio.TimeoutError, ValueError) as error:
            self.record("connect-failed", tunnel=number, host=host, error=type(error).__name__)
            writer.write(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n")
            writer.close()
            return
        # An outage may have started while connecting; this tunnel was not yet registered,
        # so the outage transition could not close it.
        if self.mode == "outage":
            upstream_writer.close()
            self.record("refused", tunnel=number, host=host)
            writer.write(b"HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\n\r\n")
            writer.close()
            return
        writer.write(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        await writer.drain()
        ingestion = host.endswith(self.suffix)
        # baseline: upstream bytes already answered when this tunnel's handshake completed or
        # when drop-next was armed. Only bytes sent after it count as the request, and mid-
        # upload downstream data (TLS tickets, HTTP/2 frames) never resets it.
        state = {"poisoned": False, "up": 0, "down": 0, "baseline": None, "close": None}

        def close():
            for stream in (writer, upstream_writer):
                if not stream.is_closing():
                    stream.close()

        state["close"] = close
        self.tunnels[number] = state
        self.record("open", tunnel=number, host=host)

        async def client_to_server():
            while data := await reader.read(65536):
                state["up"] += len(data)
                # Always forwarded, also after poisoning: Azure must receive the whole
                # upload, or the fault is a truncated request instead of a lost answer.
                upstream_writer.write(data)
                await upstream_writer.drain()
            # The client gave up (for example its delivery deadline): end the tunnel.
            close()

        async def server_to_client():
            while data := await upstream_reader.read(65536):
                # The first downstream data is the handshake reply: never dropped, and the
                # request count starts after it.
                if state["baseline"] is None:
                    state["baseline"] = state["up"]
                elif (ingestion and not state["poisoned"] and self.mode.startswith("drop-next")
                        and state["up"] - state["baseline"] >= self.request_bytes):
                    state["poisoned"] = True
                    self.poisoned += 1
                    self.record("response-dropped", tunnel=number, host=host, requestBytes=state["up"] - state["baseline"])
                    self.set_mode("outage" if self.mode == "drop-next-then-outage" else "pass")
                if state["poisoned"]:
                    continue
                state["down"] += len(data)
                writer.write(data)
                await writer.drain()

        try:
            await asyncio.gather(client_to_server(), server_to_client())
        except (ConnectionError, OSError):
            pass
        finally:
            close()
            self.tunnels.pop(number, None)
            self.record("closed", tunnel=number, host=host, up=state["up"], down=state["down"], poisoned=state["poisoned"])

    async def control(self, reader, writer):
        try:
            line = (await asyncio.wait_for(reader.readline(), 10)).decode("latin-1").split()
            await reader.readuntil(b"\r\n\r\n")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, asyncio.TimeoutError):
            writer.close()
            return
        path = line[1] if len(line) > 1 else "/"
        status = 200
        if path.startswith("/mode/") and path[6:] in MODES:
            self.set_mode(path[6:])
        elif path != "/status":
            status = 404
        body = json.dumps({"mode": self.mode, "openTunnels": len(self.tunnels), "responsesDropped": self.poisoned}).encode()
        writer.write(b"HTTP/1.1 %d OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n\r\n%s" % (status, len(body), body))
        await writer.drain()
        writer.close()


async def main(argv):
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--port", type=int, default=8899)
    parser.add_argument("--control-port", type=int, default=8898)
    parser.add_argument("--target-suffix", default=".ingest.monitor.azure.com")
    parser.add_argument("--request-bytes", type=int, default=2048)
    parser.add_argument("--log", required=True)
    args = parser.parse_args(argv)
    proxy = Proxy(args.target_suffix, args.request_bytes, args.log)
    tunnel = await asyncio.start_server(proxy.handle, "127.0.0.1", args.port)
    control = await asyncio.start_server(proxy.control, "127.0.0.1", args.control_port)
    proxy.record("started", port=args.port, controlPort=args.control_port)
    async with tunnel, control:
        await asyncio.gather(tunnel.serve_forever(), control.serve_forever())


if __name__ == "__main__":
    asyncio.run(main(sys.argv[1:]))
