#!/usr/bin/env bash
# Owned disposable lab only: swap two pinned native files, preserving all runtime state.
set -euo pipefail
umask 077
python3 - <<'PY'
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
import zipfile

FILES = ('Bower.Collector', 'libe_sqlite3.so')
MAX_BYTES = 512 * 1024 * 1024


def safe_regular(path):
    mode = path.lstat().st_mode
    if not stat.S_ISREG(mode) or path.is_symlink() or path.stat().st_uid != 0 or mode & 0o022:
        raise ValueError('Unsafe native file')


def archive_files(path, destination):
    with zipfile.ZipFile(path) as archive:
        if len(archive.infolist()) not in (2, 3):
            raise ValueError('Unexpected candidate archive entries')
        seen, total = set(), 0
        for entry in archive.infolist():
            name = entry.filename
            mode = (entry.external_attr >> 16) & 0o170000
            if (name in seen or name not in {'collector/', *('collector/' + name for name in FILES)}
                    or mode not in (0, stat.S_IFREG, stat.S_IFDIR)
                    or entry.external_attr & 1024 or entry.flag_bits & 1):
                raise ValueError('Unsafe candidate archive entry')
            seen.add(name)
            if name == 'collector/':
                if entry.file_size != 0 or mode == stat.S_IFREG:
                    raise ValueError('Invalid root directory')
                continue
            if mode == stat.S_IFDIR or not 0 < entry.file_size <= MAX_BYTES:
                raise ValueError('Invalid native entry size')
            total += entry.file_size
        if not {'collector/' + name for name in FILES} <= seen or total > MAX_BYTES:
            raise ValueError('Incomplete or oversized candidate')
        for name in FILES:
            entry = archive.getinfo('collector/' + name)
            target = destination / name
            count = 0
            with archive.open(entry) as source, target.open('xb') as output:
                while True:
                    chunk = source.read(65536)
                    if not chunk:
                        break
                    count += len(chunk)
                    if count > entry.file_size:
                        raise ValueError('Expanded candidate bound exceeded')
                    output.write(chunk)
                output.flush()
                os.fsync(output.fileno())
            if count != entry.file_size:
                raise ValueError('Expanded candidate size mismatch')
            os.chmod(target, 0o755 if name == 'Bower.Collector' else 0o644)


def hashes(directory):
    return {name: hashlib.sha256((directory / name).read_bytes()).hexdigest() for name in FILES}


def swap_pair(release, candidate, backup, stop, start, healthy):
    old, new = hashes(release), hashes(candidate)
    for name in FILES:
        shutil.copy2(release / name, backup / name)
    changed = []
    try:
        stop()
        for name in FILES:
            os.replace(candidate / name, release / name)
            changed.append(name)
        start()
        if not healthy():
            raise RuntimeError('Candidate did not become ready')
        return {'updated': True, 'oldSha256': old, 'newSha256': new, 'rollbackPerformed': False}
    except Exception:
        restored = False
        try:
            stop()
            for name in FILES:
                temporary = backup / (name + '.restore')
                shutil.copy2(backup / name, temporary)
                os.replace(temporary, release / name)
            start()
            restored = healthy() and hashes(release) == old
        except Exception:
            restored = False
        return {'updated': False, 'oldSha256': old, 'newSha256': new, 'rollbackPerformed': True,
                'rollbackSucceeded': restored, 'filesChanged': changed}


def main():
    run, bucket = os.environ['BOWER_LAB_RUN'], os.environ['BOWER_LAB_BUCKET']
    commit, expected = os.environ['BOWER_CANDIDATE_COMMIT'], os.environ['BOWER_CANDIDATE_SHA256']
    if (os.geteuid() != 0 or not re.fullmatch(r'bower-ws6-\d{8}-\d{6}', run)
            or not re.fullmatch(r'[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]', bucket)
            or not re.fullmatch(r'[a-f0-9]{40}', commit) or not re.fullmatch(r'[a-f0-9]{64}', expected)
            or os.environ.get('AWS_DEFAULT_REGION') != 'ap-southeast-2'):
        raise ValueError('Invalid owned candidate scope')
    def command(*args):
        result = subprocess.run(args, capture_output=True, text=True, timeout=180)
        if result.returncode:
            raise RuntimeError('Candidate operation failed')
        return result.stdout.strip()
    if command('aws', '--region', 'ap-southeast-2', 'sts', 'get-caller-identity', '--query', 'Account', '--output', 'text') != '959038055523':
        raise ValueError('Wrong AWS account')
    if json.loads(Path('/var/lib/bower-lab/qualification-owner.json').read_text()) != {'runId': run, 'role': 'collector'}:
        raise ValueError('Wrong collector owner')
    with Path('/var/lib/bower-lab/candidate-update.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if command('systemctl', 'show', 'bower.service', '--property=User', '--value') != 'bower':
            raise ValueError('Wrong service user')
        if command('systemctl', 'is-active', 'bower.service') != 'active':
            raise ValueError('Original service is not active')
        release = Path(command('systemctl', 'show', 'bower.service', '--property=WorkingDirectory', '--value'))
        if release.parent != Path('/opt/bower/releases') or not release.name.startswith(run + '-') or release.resolve() != release:
            raise ValueError('Service release is outside owned run')
        for directory in (release, *release.parents):
            info = directory.lstat()
            if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:
                raise ValueError('Unsafe install directory')
        for name in FILES:
            safe_regular(release / name)
        pid = int(command('systemctl', 'show', 'bower.service', '--property=MainPID', '--value'))
        if pid < 1 or Path('/proc/' + str(pid) + '/exe').resolve() != release / 'Bower.Collector':
            raise ValueError('Unexpected active executable')
        tables = json.loads(command('nft', '-j', 'list', 'tables'))
        if any(item.get('table', {}).get('name', '').startswith('bower_outage_') for item in tables['nftables']):
            raise ValueError('Do not update during a destination outage')
        token = Path('/etc/bower/secrets/token').read_text().strip()
        def queue_counts():
            connection = http.client.HTTPConnection('127.0.0.1', 4319, timeout=5)
            try:
                connection.request('GET', '/v1/status', headers={'Authorization': 'Bearer ' + token})
                response = connection.getresponse()
                data = response.read(65537)
                if response.status != 200 or len(data) > 65536:
                    raise ValueError('Status unavailable or oversized')
                queue = json.loads(data)['queue']
                fields = ('queued', 'retrying', 'uploading', 'delivered', 'deadLettered', 'totalBytes', 'undeliveredBytes')
                if any(type(queue.get(key)) is not int or queue[key] < 0 for key in fields):
                    raise ValueError('Malformed queue count')
                return {key: queue[key] for key in fields}
            finally:
                connection.close()
        before = queue_counts()
        key = 'artifacts/qualification/{}/candidate/{}/linux/collector.zip'.format(run, commit)
        size = int(command('aws', '--region', 'ap-southeast-2', 's3api', 'head-object', '--bucket', bucket,
                           '--key', key, '--query', 'ContentLength', '--output', 'text'))
        if not 0 < size <= MAX_BYTES:
            raise ValueError('Candidate download bound exceeded')
        with tempfile.TemporaryDirectory(prefix='.candidate-', dir=release.parent) as temporary:
            stage = Path(temporary)
            archive = stage / 'collector.zip'
            command('aws', '--region', 'ap-southeast-2', 's3', 'cp', 's3://' + bucket + '/' + key, str(archive), '--only-show-errors')
            if archive.stat().st_size != size or hashlib.sha256(archive.read_bytes()).hexdigest() != expected:
                raise ValueError('Candidate archive digest mismatch')
            archive_files(archive, stage)
            backup = release / ('.rollback-' + commit + '-' + uuid.uuid4().hex)
            backup.mkdir(mode=0o700)
            def stop():
                command('systemctl', 'stop', 'bower.service')
                if command('systemctl', 'show', 'bower.service', '--property=ActiveState', '--value') != 'inactive':
                    raise RuntimeError('Service did not stop')
            def start():
                command('systemctl', 'start', 'bower.service')
            def healthy():
                for attempt in range(30):
                    try:
                        if command('systemctl', 'is-active', 'bower.service') == 'active':
                            queue_counts()
                            return True
                    except Exception:
                        pass
                    time.sleep(2)
                return False
            result = swap_pair(release, stage, backup, stop, start, healthy)
            result.update(runId=run, candidateCommit=commit, archiveSha256=expected, rollbackDirectory=str(backup), queueBefore=before,
                          configurationChanged=False, queueReplaced=False, destinationQueryVerified=False)
            result['serviceReady'] = result['updated'] or result.get('rollbackSucceeded', False)
            try:
                result['queueAfter'] = queue_counts()
            except Exception:
                result['queueAfter'] = None
            print(json.dumps(result))
            return 0 if result['updated'] else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as error:
        print(json.dumps({'candidateUpdate': 'failed', 'category': type(error).__name__}), file=sys.stderr)
        sys.exit(1)
PY
