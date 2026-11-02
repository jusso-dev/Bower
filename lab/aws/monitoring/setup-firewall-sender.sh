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
export BOWER_LAB_HOST=SenderR
: "${BOWER_SYSLOG_COLLECTOR_IP:?}"
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

from types import SimpleNamespace

REQUIRED = {"syslog-host.py": 1024 * 1024, "sender-r.pem": 65536, "sender-r-key.pem": 65536, "ca.pem": 65536}

def local_certificate_fetch(stage, key, destination, sha256=None):
    allowed = {"exchange/ca.pem": ("ca.pem", Path("/etc/pki/bower-lab/ca.pem")),
               "exchange/sender-r.pem": ("sender-r.pem", Path("/etc/pki/bower-lab/sender-r.pem"))}
    if key not in allowed or Path(destination) != allowed[key][1]:
        fail("unexpected-certificate-fetch")
    source = stage / allowed[key][0]
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    if sha256 is not None and sha256 != digest:
        fail("certificate-fetch-digest-mismatch")
    install_file(source, destination, 0o644)
    return digest

stage, run, manifest_hash = fetch_artifacts("sender", REQUIRED)
peer = private_ip(os.environ["BOWER_SYSLOG_COLLECTOR_IP"])
# omfwd (the recommended TLS profile, default) or relp (omrelp over mutual TLS).
transport = os.environ.get("BOWER_SYSLOG_TRANSPORT", "omfwd")
if transport not in ("omfwd", "relp"):
    fail("unsupported-sender-transport")
verify_certificate(stage, "sender-r.pem", "sender-r-key.pem", "sslclient")
verify_run_marker(run, "sender")
pki = Path("/etc/pki/bower-lab")
pki.mkdir(parents=True, mode=0o700, exist_ok=True)
os.chmod(pki, 0o700)
for name in ("ca.pem", "sender-r.pem", "sender-r-key.pem"):
    install_file(stage / name, pki / name, 0o600 if name.endswith("-key.pem") else 0o644)
tool = install_tool(stage)
with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
    tool.install_sender(SimpleNamespace(docker=False))
relp_build = None
if transport == "relp":
    output = io.StringIO()
    with contextlib.redirect_stdout(output), contextlib.redirect_stderr(io.StringIO()):
        tool.install_relp()
    relp_build = json.loads(output.getvalue())
# Use the exact reviewed recommended profile. The only substituted operation is
# fetching the two already-verified public certificates from the local stage;
# no exchange/* S3 permission is granted and no TLS verification is bypassed.
tool.fetch = lambda key, destination, sha256=None: local_certificate_fetch(stage, key, destination, sha256)
if command("systemctl", "show", "rsyslog.service", "--property=User", "--value") not in ("", "root"):
    fail("sender-profile-requires-default-root-rsyslog-service")
journal_directory = Path("/etc/systemd/journald.conf.d")
journal_directory.mkdir(parents=True, exist_ok=True)
(stage / "journald.conf").write_text("[Journal]\nStorage=persistent\nSystemMaxUse=1G\nRuntimeMaxUse=256M\n"
                                    "RateLimitIntervalSec=30s\nRateLimitBurst=200000\n")
install_file(stage / "journald.conf", journal_directory / "60-bower-qualification.conf", 0o644)
command("systemctl", "restart", "systemd-journald.service")
command("journalctl", "--flush")
with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(io.StringIO()):
    tool.configure_rsyslog(SimpleNamespace(a=peer, b=peer, cert="sender-r", transport=transport,
                                          profile="recommended", rebind=0, only="a13", queue="recommended"))
configuration = Path("/etc/rsyslog.d/10-bower-lab.conf").read_text()
base_configuration = Path("/etc/rsyslog.conf").read_text()
if not (re.search(r'workDirectory\s*=\s*"/var/lib/rsyslog"', base_configuration, re.I)
        or re.search(r"^\s*\$WorkDirectory\s+/var/lib/rsyslog\s*$", base_configuration, re.M | re.I)):
    fail("rsyslog-work-directory-is-not-persistent")
queue_settings = ('queue.size="200000"', 'queue.highWatermark="150000"', 'queue.lowWatermark="100000"',
                  'queue.maxDiskSpace="2g"', 'queue.timeoutEnqueue="86400000"', 'queue.saveOnShutdown="on"',
                  'queue.discardMark="200000"', 'queue.discardSeverity="8"',
                  'queue.checkpointInterval="100"', 'queue.syncQueueFiles="off"', 'action.resumeRetryCount="-1"')
if transport == "relp":
    required_settings = queue_settings + (
        'module(load="omrelp" tls.tlslib="openssl")', 'tls="on"', 'tls.authmode="name"',
        'tls.permittedpeer=["collector-a.bower.lab"]', 'windowSize="128"', 'timeout="90"',
        'rebindInterval="0"', 'template="RSYSLOG_SyslogProtocol23Format"')
else:
    required_settings = queue_settings + (
        'RebindInterval="0"', 'ResendLastMSGOnReconnect="on"', 'KeepAlive="on"',
        'KeepAlive.Time="60"', 'KeepAlive.Interval="10"', 'KeepAlive.Probes="6"',
        'StreamDriverAuthMode="x509/name"', 'StreamDriverPermittedPeers="collector-a.bower.lab"',
        'TCP_Framing="octet-counted"')
if any(setting not in configuration for setting in required_settings):
    fail("recommended-sender-profile-mismatch")
if configuration.count('type="' + ("omrelp" if transport == "relp" else "omfwd") + '"') != 1 or 'port="6514"' not in configuration:
    fail("sender-must-forward-only-a13")
if 'Ratelimit.Burst="200000"' not in base_configuration:
    fail("imjournal-rate-bound-missing")
if command("systemctl", "is-active", "rsyslog.service") != "active":
    fail("sender-not-active")
print(json.dumps({"phase": "firewall-sender-setup", "runId": run, "manifestSha256": manifest_hash,
                  "profile": "recommended", "transport": transport, "relpBuild": relp_build,
                  "listener": "a13", "port": 6514,
                  "senderConfigSha256": hashlib.sha256(configuration.encode()).hexdigest(),
                  "sourceToolSha256": hashlib.sha256((stage / "syslog-host.py").read_bytes()).hexdigest(),
                  "journalStorage": "persistent", "nftCounters": tool.nft_packets(),
                  "deliveryQualified": False}))

PY
