"""Bower security events for Python web apps (Django, Flask, FastAPI). Standard library only.

Builds Bower envelope 1.0.0 events, sanitises them before they leave the process (no CR or
LF, no secret-named fields, no query strings, bounded strings) and posts them to a Bower
collector. The collector redacts again: this is defence in depth, not the only control.
"""

from __future__ import annotations

import ipaddress
import json
import os
import re
import threading
import urllib.request
import uuid
from datetime import datetime, timezone
from typing import Any, Iterable, Mapping

SCHEMA_VERSION = "1.0.0"
_CONTROL = re.compile("[\x00-\x1f\x7f\u2028\u2029]+")
_SECRET_FRAGMENTS = ("password", "passwd", "passphrase", "secret", "token", "apikey", "cookie",
                     "authorization", "credential", "privatekey", "signature")
_SECRET_NAMES = {"body", "rawbody", "requestbody", "responsebody", "headers", "payload", "otp", "otpcode",
                 "totp", "mfacode", "verificationcode", "recoverycode", "backupcode", "stacktrace",
                 "exceptionmessage", "statement", "querytext", "sqltext", "querystring", "rawquery"}
_LIMITS = {"eventOutcomeReason": 1024, "path": 2048}


def _is_secret(name: str) -> bool:
    normal = re.sub(r"[^a-z0-9]", "", name.lower())
    return normal in _SECRET_NAMES or any(fragment in normal for fragment in _SECRET_FRAGMENTS)


def _clean(value: Any, key: str = "") -> Any:
    if isinstance(value, str):
        text = _CONTROL.sub(" ", value)
        return text[: _LIMITS.get(key, 256)]
    if isinstance(value, Mapping):
        out = {}
        for name, item in value.items():
            if _is_secret(str(name)) or item is None:
                continue
            cleaned = _clean(item, str(name))
            if cleaned == {}:
                continue
            out[_CONTROL.sub(" ", str(name))[:128]] = cleaned
        return out
    if isinstance(value, (list, tuple)):
        return [_clean(item) for item in value][:64]
    return value


def format_time(moment: datetime) -> str:
    """UTC, millisecond precision, Z suffix (ASVS 5.0 V16.2.2)."""
    utc = moment.astimezone(timezone.utc)
    return utc.strftime("%Y-%m-%dT%H:%M:%S.") + f"{utc.microsecond // 1000:03d}Z"


def build_event(app: Mapping[str, Any], spec: Mapping[str, Any], *, event_id: str | None = None,
                now: datetime | None = None) -> dict[str, Any]:
    """Build a sanitised envelope. `spec` keys: eventType, eventCategory, eventAction,
    eventResult, eventSeverity, reason, actor, target, sourceIp, userAgent, route, tenantId,
    request, labels, attributes, change."""
    application = {k: app[k] for k in ("name", "environment", "version", "instance") if app.get(k)}
    if spec.get("tenantId"):
        application["tenantId"] = spec["tenantId"]
    event: dict[str, Any] = {
        "schemaVersion": SCHEMA_VERSION,
        "eventId": event_id or str(uuid.uuid4()),
        "timeGenerated": format_time(now or datetime.now(timezone.utc)),
        "eventCategory": spec["eventCategory"],
        "eventType": spec["eventType"],
        "eventAction": spec["eventAction"],
        "eventResult": spec["eventResult"],
        "eventSeverity": spec.get("eventSeverity", "informational"),
        "application": application,
    }
    if spec.get("reason"):
        event["eventOutcomeReason"] = spec["reason"]
    for part in ("actor", "target"):
        if spec.get(part):
            event[part] = dict(spec[part])
    if spec.get("sourceIp"):
        event["source"] = {"ipAddress": spec["sourceIp"]}
    request = dict(spec.get("request") or {})
    if request.get("path"):
        request["path"] = re.split(r"[?#]", request["path"], maxsplit=1)[0]
    if request:
        event["request"] = request
    labels = dict(spec.get("labels") or {})
    if spec.get("userAgent"):
        labels["userAgent"] = spec["userAgent"]
    if spec.get("route"):
        labels["route"] = spec["route"]
    if labels:
        event["labels"] = {k: str(v) for k, v in labels.items()}
    if spec.get("attributes"):
        event["attributes"] = dict(spec["attributes"])
    change = dict(spec.get("change") or {})
    if change and spec["eventType"] != "role_membership_changed":
        # Before and after values of settings and credentials never leave the process.
        change = {"field": change["field"]} if "field" in change else {}
    if change:
        event["change"] = change
    return _clean(event)


def canonical(event: Mapping[str, Any]) -> str:
    """Sorted, compact JSON: the cross-language contract form."""
    return json.dumps(event, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def client_ip(remote_addr: str, forwarded_for: str | None, trusted_proxies: Iterable[str]) -> str:
    """Original client address (ASVS 5.0 V15.3.4, V4.1.3). X-Forwarded-For is read only
    when the direct peer is a trusted proxy, right to left, skipping trusted hops."""
    networks = [ipaddress.ip_network(item, strict=False) for item in trusted_proxies]

    def trusted(address: str) -> bool:
        try:
            ip = ipaddress.ip_address(address)
        except ValueError:
            return False
        return any(ip in network for network in networks)

    if not forwarded_for or not trusted(remote_addr):
        return remote_addr
    hops = [hop.strip() for hop in forwarded_for.split(",") if hop.strip()]
    for hop in reversed(hops):
        if not trusted(hop):
            try:
                return str(ipaddress.ip_address(hop))
            except ValueError:
                return remote_addr
    return hops[0] if hops else remote_addr


class BowerClient:
    """Posts events to a Bower collector. Never raises into the request path."""

    def __init__(self, endpoint: str | None = None, token: str | None = None, timeout: float = 2.0):
        self.endpoint = (endpoint or os.environ.get("BOWER_COLLECTOR_URL", "http://127.0.0.1:4319")).rstrip("/")
        self.token = token if token is not None else os.environ.get("BOWER_INGEST_TOKEN")
        self.timeout = timeout

    def send(self, event: Mapping[str, Any]) -> int | None:
        body = json.dumps(event, separators=(",", ":")).encode("utf-8")
        request = urllib.request.Request(f"{self.endpoint}/v1/events", data=body, method="POST",
                                         headers={"Content-Type": "application/json"})
        if self.token:
            request.add_header("Authorization", f"Bearer {self.token}")
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                return response.status
        except urllib.error.HTTPError as error:
            return error.code
        except OSError:
            return None

    def send_async(self, event: Mapping[str, Any]) -> None:
        threading.Thread(target=self.send, args=(event,), daemon=True).start()
