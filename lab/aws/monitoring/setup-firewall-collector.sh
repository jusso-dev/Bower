#!/bin/bash
# Owned disposable lab only; downloads pinned artifacts and never prints credentials.
set +x
set -euo pipefail
umask 077
: "${BOWER_LAB_BUCKET:?}" "${BOWER_LAB_RUN:?}" "${BOWER_ARTIFACT_MANIFEST_SHA256:?}"
stage=$(mktemp -d)
trap 'rm -rf -- "$stage"' EXIT
trap 'echo "firewall setup failed at line $LINENO" >&2' ERR
export BOWER_SETUP_STAGE="$stage"
export BOWER_LAB_HOST=CollectorA
: "${BOWER_SYSLOG_SENDER_IP:?}"
python3 - <<'PY'
import contextlib
import hashlib
import importlib.util
import io
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

class SetupError(Exception):
    pass

def fail(code):
    raise SetupError(code)

def safe_exception(kind, error, traceback):
    print("firewall-setup: " + (str(error) if isinstance(error, SetupError) else kind.__name__), file=sys.stderr)

sys.excepthook = safe_exception

def command(*args):
    result = subprocess.run(args, capture_output=True, check=True, text=True, timeout=300)
    return result.stdout.strip()

def private_ip(value):
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        fail("invalid-peer-address")
    networks = [ipaddress.ip_network(cidr) for cidr in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]
    if address.version != 4 or not any(address in network for network in networks):
        fail("peer-must-be-private-ipv4")
    return str(address)

def fetch_artifacts(role, required):
    run = os.environ["BOWER_LAB_RUN"]
    bucket = os.environ["BOWER_LAB_BUCKET"]
    expected_manifest = os.environ["BOWER_ARTIFACT_MANIFEST_SHA256"]
    if os.geteuid() != 0 or not re.fullmatch(r"bower-(?:ws6|fw|soak)-\d{8}-\d{6}", run):
        fail("not-an-owned-root-drill")
    if not re.fullmatch(r"[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]", bucket):
        fail("invalid-artifact-bucket")
    if not re.fullmatch(r"[0-9a-f]{64}", expected_manifest):
        fail("invalid-manifest-digest")
    if os.environ.get("AWS_DEFAULT_REGION") != "ap-southeast-2":
        fail("unexpected-aws-region")
    if command("aws", "sts", "get-caller-identity", "--query", "Account", "--output", "text") != "959038055523":
        fail("unexpected-aws-account")
    stage = Path(os.environ["BOWER_SETUP_STAGE"])
    prefix = "artifacts/qualification/" + run + "/" + role + "/"

    def download(name, limit, expected_size=None):
        key = prefix + name
        size = int(command("aws", "s3api", "head-object", "--bucket", bucket, "--key", key,
                           "--query", "ContentLength", "--output", "text"))
        if size <= 0 or size > limit or (expected_size is not None and size != expected_size):
            fail("artifact-size-mismatch")
        path = stage / name
        command("aws", "s3", "cp", "--only-show-errors", "s3://" + bucket + "/" + key, str(path))
        if path.stat().st_size != size:
            fail("artifact-size-changed")
        os.chmod(path, 0o600)
        return path

    manifest_path = download("manifest.json", 65536)
    if hashlib.sha256(manifest_path.read_bytes()).hexdigest() != expected_manifest:
        fail("manifest-digest-mismatch")
    manifest = json.loads(manifest_path.read_text())
    if manifest.get("schemaVersion") != 1 or manifest.get("runId") != run or manifest.get("role") != role:
        fail("manifest-identity-mismatch")
    files = manifest.get("files")
    if not isinstance(files, dict) or set(files) != set(required):
        fail("manifest-file-set-mismatch")
    for name, limit in required.items():
        entry = files[name]
        if (not isinstance(entry, dict) or set(entry) != {"sha256", "bytes"}
                or type(entry["bytes"]) is not int or not 0 < entry["bytes"] <= limit
                or not isinstance(entry["sha256"], str) or not re.fullmatch(r"[0-9a-f]{64}", entry["sha256"])):
            fail("invalid-artifact-entry")
        path = download(name, limit, entry["bytes"])
        if hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
            fail("artifact-digest-mismatch")
    return stage, run, expected_manifest

def install_file(source, destination, mode=0o600, group=None):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)
    temporary = destination.with_name(destination.name + ".setup-new")
    if temporary.is_symlink():
        fail("unexpected-temporary-symlink")
    shutil.copyfile(source, temporary)
    os.chmod(temporary, mode)
    shutil.chown(temporary, "root", group or "root")
    os.replace(temporary, destination)

def verify_certificate(stage, certificate, private_key, purpose, hostname=None):
    args = ["openssl", "verify", "-CAfile", str(stage / "ca.pem"), "-purpose", purpose]
    if hostname:
        args.extend(["-verify_hostname", hostname])
    command(*args, str(stage / certificate))
    cert_public = command("openssl", "x509", "-in", str(stage / certificate), "-pubkey", "-noout")
    key_public = command("openssl", "pkey", "-in", str(stage / private_key), "-pubout")
    if cert_public != key_public:
        fail("certificate-key-mismatch")

def install_tool(stage):
    target = Path("/opt/bower-lab/syslog-host.py")
    target.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(target.parent, 0o755)
    install_file(stage / "syslog-host.py", target, 0o755)
    spec = importlib.util.spec_from_file_location("qualified_syslog_host", target)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module

def verify_run_marker(run, role):
    directory = Path("/var/lib/bower-lab")
    directory.mkdir(mode=0o700, exist_ok=True)
    marker = directory / "qualification-owner.json"
    expected = {"runId": run, "role": role}
    if marker.exists() and json.loads(marker.read_text()) != expected:
        fail("host-already-belongs-to-another-qualification")
    marker.write_text(json.dumps(expected) + "\n")
    os.chmod(marker, 0o600)

import tarfile
import tempfile
import http.client
import time
from types import SimpleNamespace
import uuid
from urllib.parse import urlsplit

REQUIRED = {"collector.tar.gz": 512 * 1024 * 1024, "sentinel.env": 65536,
            "ingest.pem": 65536, "ingest-token": 4096, "syslog-reliability.bowerpack": 16 * 1024 * 1024,
            "pack-signing.pub.pem": 65536, "collector-health.yaml": 65536,
            "server.pem": 65536, "server-key.pem": 65536, "ca.pem": 65536, "syslog-host.py": 1024 * 1024}
DESTINATION_KEYS = {"BOWER_OUTPUT", "BOWER_DCE_ENDPOINT", "BOWER_DCR_ID", "BOWER_STREAM_NAME",
                    "BOWER_AZURE_CREDENTIAL", "AZURE_TENANT_ID", "AZURE_CLIENT_ID",
                    "AZURE_CLIENT_CERTIFICATE_PATH", "AZURE_CLIENT_SEND_CERTIFICATE_CHAIN"}

def parse_environment(text, destination_only=False):
    values = {}
    for line in text.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, value = line.partition("=")
        if not separator or not re.fullmatch(r"[A-Z][A-Z0-9_]*", key) or key in values:
            fail("invalid-environment-file")
        if value.startswith(("'", '"')):
            if len(value) < 2 or value[-1] != value[0]:
                fail("invalid-environment-quote")
            value = value[1:-1]
        if any(c in value for c in "\r\n\x00") or (destination_only and key not in DESTINATION_KEYS):
            fail("unsupported-environment-setting")
        values[key] = value
    return values

def destination_environment(text):
    values = parse_environment(text, destination_only=True)
    if values.get("BOWER_OUTPUT") != "azure-logs-ingestion" or values.get("BOWER_AZURE_CREDENTIAL") != "environment":
        fail("sentinel-certificate-output-required")
    endpoint = urlsplit(values.get("BOWER_DCE_ENDPOINT", ""))
    if endpoint.scheme != "https" or not endpoint.hostname or endpoint.username or endpoint.password or endpoint.query or endpoint.fragment:
        fail("invalid-sentinel-endpoint")
    if not re.fullmatch(r"dcr-[0-9a-fA-F]{32}", values.get("BOWER_DCR_ID", "")):
        fail("invalid-dcr-id")
    for name in ("AZURE_TENANT_ID", "AZURE_CLIENT_ID"):
        try:
            uuid.UUID(values.get(name, ""))
        except ValueError:
            fail("invalid-azure-identity")
    if values.get("AZURE_CLIENT_CERTIFICATE_PATH") != "/etc/bower/secrets/ingest.pem":
        fail("unexpected-ingestion-certificate-path")
    values.setdefault("BOWER_STREAM_NAME", "Custom-BowerSecurity")
    return values

def validate_archive(path):
    with tarfile.open(path, "r:gz") as archive:
        names = set()
        application_present = False
        total_bytes = 0
        for member in archive:
            total_bytes += member.size
            if len(names) >= 10000 or total_bytes > 1024 * 1024 * 1024:
                fail("collector-archive-too-large")
            parts = Path(member.name).parts
            normalized = Path(member.name).as_posix()
            if (not parts or parts[0] != "collector" or member.name.startswith("/") or ".." in parts
                    or not (member.isfile() or member.isdir()) or normalized in names):
                fail("unsafe-collector-archive")
            names.add(normalized)
            application_present |= normalized == "collector/Bower.Collector" and member.isfile()
        if not application_present:
            fail("collector-binary-missing")

def wait_for_collector():
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline:
        connection = http.client.HTTPConnection("127.0.0.1", 4319, timeout=5)
        try:
            connection.request("GET", "/health")
            response = connection.getresponse()
            if response.status == 200:
                return
        except (OSError, http.client.HTTPException):
            pass
        finally:
            connection.close()
        time.sleep(2)
    fail("collector-health-not-ready")

# tarball (default): the native publish output under /opt/bower/releases with a lab unit.
# rpm: the CI-built package and its packaged bower.service (the soak installs from main).
package = os.environ.get("BOWER_COLLECTOR_PACKAGE", "tarball")
if package not in ("tarball", "rpm"):
    fail("unsupported-collector-package")
if package == "rpm":
    REQUIRED["collector.rpm"] = REQUIRED.pop("collector.tar.gz")
stage, run, manifest_hash = fetch_artifacts("collector", REQUIRED)
peer = private_ip(os.environ["BOWER_SYSLOG_SENDER_IP"])
# tls (default) or relp: the same mutual-TLS material on listener a13, port 6514.
protocol = os.environ.get("BOWER_SYSLOG_PROTOCOL", "tls")
if protocol not in ("tls", "relp"):
    fail("unsupported-syslog-protocol")
# Optional undelivered-queue cap for the queue-capacity scenario (16 MiB to 1 GiB).
queue_cap = os.environ.get("BOWER_QUEUE_MAX_BYTES", "")
if queue_cap and (not re.fullmatch(r"[0-9]{8,10}", queue_cap) or not 16777216 <= int(queue_cap) <= 1073741824):
    fail("invalid-queue-cap")
# Optional acknowledged-event retention (hours) so the hourly retention job prunes in long runs.
retention = os.environ.get("BOWER_QUEUE_RETENTION_HOURS", "")
if retention and (not re.fullmatch(r"[0-9]{1,4}", retention) or not 1 <= int(retention) <= 2160):
    fail("invalid-queue-retention")
destination = destination_environment((stage / "sentinel.env").read_text())
existing_env = Path("/etc/bower/bower.env")
if existing_env.exists():
    existing = parse_environment(existing_env.read_text())
    for key in DESTINATION_KEYS:
        if key in existing and existing[key] != destination.get(key):
            fail("refusing-to-change-existing-sentinel-destination")
verify_certificate(stage, "server.pem", "server-key.pem", "sslserver", "collector-a.bower.lab")
if package == "tarball":
    validate_archive(stage / "collector.tar.gz")
verify_run_marker(run, "collector")
command("dnf", "-y", "-q", "install", "libicu", "nftables", "tar", "gzip")
if package == "rpm":
    # The package creates the bower user, the directories and enables bower.service.
    command("dnf", "-y", "-q", "install", str(stage / "collector.rpm"))
    release = Path("/opt/bower")
else:
    if subprocess.run(["id", "bower"], capture_output=True).returncode:
        command("useradd", "--system", "--home-dir", "/var/lib/bower", "--shell", "/sbin/nologin", "bower")
    for directory in ("/opt/bower", "/opt/bower/releases"):
        Path(directory).mkdir(parents=True, exist_ok=True)
        os.chmod(directory, 0o755)
    release = Path(tempfile.mkdtemp(prefix=run + "-" + manifest_hash[:16] + "-", dir="/opt/bower/releases"))
    os.chmod(release, 0o755)
    command("tar", "--extract", "--gzip", "--file", str(stage / "collector.tar.gz"), "--directory", str(release),
            "--strip-components=1", "--no-same-owner", "--no-same-permissions")
    for path in release.rglob("*"):
        os.chmod(path, 0o755 if path.is_dir() else 0o644)
    os.chmod(release / "Bower.Collector", 0o755)
loaded = subprocess.run(["systemctl", "show", "bower.service", "--property=LoadState", "--value"],
                        capture_output=True, text=True)
if loaded.stdout.strip() != "not-found":
    command("systemctl", "stop", "bower.service")
for directory in ("/etc/bower", "/etc/bower/secrets", "/etc/bower/keys", "/etc/bower/packs",
                  "/etc/bower/syslog", "/etc/bower/policies-firewall-qualification"):
    Path(directory).mkdir(parents=True, exist_ok=True)
    shutil.chown(directory, "root", "bower")
    os.chmod(directory, 0o750)
for directory in ("/var/lib/bower", "/var/spool/bower"):
    Path(directory).mkdir(parents=True, exist_ok=True)
    shutil.chown(directory, "bower", "bower")
    os.chmod(directory, 0o700)
for name, destination_path in {
        "ingest.pem": "/etc/bower/secrets/ingest.pem", "ingest-token": "/etc/bower/secrets/token",
        "syslog-reliability.bowerpack": "/etc/bower/packs/syslog-reliability.bowerpack",
        "pack-signing.pub.pem": "/etc/bower/keys/pack-signing.pub.pem",
        "collector-health.yaml": "/etc/bower/policies-firewall-qualification/collector-health.yaml",
        "server.pem": "/etc/bower/syslog/server.pem", "server-key.pem": "/etc/bower/syslog/server-key.pem",
        "ca.pem": "/etc/bower/syslog/ca.pem"}.items():
    install_file(stage / name, destination_path, 0o640, "bower")
syslog = {"apiVersion": "bower.security/v1", "kind": "SyslogSource", "listeners": [{
    "id": "a13", "protocol": protocol, "address": "0.0.0.0", "port": 6514, "allowedSenders": [peer],
    "idleTimeoutSeconds": 0, "frameTimeoutSeconds": 60, "handshakeStartTimeoutSeconds": 60,
    "tls": {"certificateFile": "/etc/bower/syslog/server.pem", "privateKeyFile": "/etc/bower/syslog/server-key.pem",
            "clientCertificateAuthorityFile": "/etc/bower/syslog/ca.pem"},
    "routes": [{"appName": "kernel", "pack": "syslog-reliability", "parser": 0},
               {"appName": "bowerseq", "pack": "syslog-reliability", "parser": 1}]}]}
(stage / "syslog.json").write_text(json.dumps(syslog) + "\n")
install_file(stage / "syslog.json", "/etc/bower/syslog.json", 0o640, "bower")
destination.update({
    "BOWER_COLLECTOR_ID": run + "-linux", "BOWER_ENVIRONMENT": "validation",
    "BOWER_LISTEN_URL": "http://127.0.0.1:4319", "BOWER_QUEUE_PATH": "/var/lib/bower/queue.db",
    "BOWER_POLICY_DIRECTORY": "/etc/bower/policies-firewall-qualification",
    "BOWER_PACKS": "/etc/bower/packs/syslog-reliability.bowerpack",
    "BOWER_PACK_TRUSTED_KEYS": "/etc/bower/keys/pack-signing.pub.pem",
    "BOWER_SYSLOG_CONFIG": "/etc/bower/syslog.json", "BOWER_INGEST_TOKEN_FILE": "/etc/bower/secrets/token",
    "BOWER_HEALTH_RECORD_INTERVAL_SECONDS": "60"})
if queue_cap:
    destination["BOWER_QUEUE_MAX_BYTES"] = queue_cap
if retention:
    destination["BOWER_QUEUE_RETENTION_HOURS"] = retention
(stage / "bower.env").write_text("".join(key + "=" + value + "\n" for key, value in sorted(destination.items())))
install_file(stage / "bower.env", existing_env, 0o640, "bower")
unit = """[Unit]
Description=Bower isolated firewall qualification collector
After=network-online.target
Wants=network-online.target
[Service]
Type=exec
User=bower
Group=bower
WorkingDirectory={release}
ExecStart={release}/Bower.Collector
EnvironmentFile=/etc/bower/bower.env
Restart=on-failure
RestartSec=5s
StateDirectory=bower
StateDirectoryMode=0700
LogsDirectory=bower
UMask=0077
CapabilityBoundingSet=
AmbientCapabilities=
NoNewPrivileges=true
PrivateTmp=true
PrivateDevices=true
ProtectSystem=strict
ProtectHome=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictNamespaces=true
LockPersonality=true
ReadWritePaths=/var/lib/bower /var/spool/bower
[Install]
WantedBy=multi-user.target
""".format(release=release)
if package == "tarball":
    (stage / "bower.service").write_text(unit)
    install_file(stage / "bower.service", "/etc/systemd/system/bower.service", 0o644)
tool = install_tool(stage)
with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
    tool.collector_tickets(SimpleNamespace(mode="disable"))
command("systemctl", "enable", "bower.service")
if command("systemctl", "is-active", "bower.service") != "active":
    fail("collector-not-active")
wait_for_collector()
print(json.dumps({"phase": "firewall-collector-setup", "runId": run, "manifestSha256": manifest_hash,
                  "collectorSha256": hashlib.sha256((release / "Bower.Collector").read_bytes()).hexdigest(),
                  "syslogConfigSha256": hashlib.sha256(Path("/etc/bower/syslog.json").read_bytes()).hexdigest(),
                  "listener": "a13", "protocol": protocol, "port": 6514, "queueMaxBytes": queue_cap or None,
                  "package": package, "packageVersion": command("rpm", "-q", "bower-collector") if package == "rpm" else None,
                  "queueRetentionHours": retention or None,
                  "output": "azure-logs-ingestion", "tls13Tickets": 0,
                  "destinationQueryVerified": False}))

PY
