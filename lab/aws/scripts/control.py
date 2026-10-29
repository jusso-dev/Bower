"""Initialise the isolated management host; secret values never leave this host's output."""
import base64
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import subprocess
import tarfile
import time
import urllib.request

ROOT = Path('/opt/bower-lab')
RUN = os.environ['BOWER_LAB_RUN']
BUCKET = os.environ['BOWER_LAB_BUCKET']
REGION = os.environ['AWS_DEFAULT_REGION']


def run(*args):
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def aws(*args):
    out = run('aws', '--region', REGION, *args, '--output', 'json')
    return json.loads(out) if out.strip() else {}


def write(path, content, mode=0o600):
    target = Path(path)
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding='utf-8')
    target.chmod(mode)


def api(path, body=None):
    payload = json.dumps(body).encode() if body is not None else None
    request = urllib.request.Request('http://127.0.0.1:4320' + path, data=payload,
        headers={'Content-Type': 'application/json'})
    with urllib.request.urlopen(request, timeout=20) as response:
        return json.load(response)


def certificate(name, usage, ip=None):
    key, csr, cert = [ROOT / 'pki' / (name + suffix) for suffix in ('.key', '.csr', '.crt')]
    if not cert.exists():
        run('openssl', 'req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:P-256', '-nodes',
            '-subj', '/CN=' + name, '-keyout', str(key), '-out', str(csr))
        extension = 'basicConstraints=CA:FALSE\nextendedKeyUsage=' + usage + '\n'
        if ip:
            extension += 'subjectAltName=IP:' + ip + '\n'
        write(ROOT / 'pki' / (name + '.ext'), extension)
        run('openssl', 'x509', '-req', '-in', str(csr), '-CA', str(ROOT/'pki/ca.crt'),
            '-CAkey', str(ROOT/'pki/ca.key'), '-CAcreateserial', '-days', '2', '-extfile',
            str(ROOT/'pki'/(name+'.ext')), '-out', str(cert))
    return key, cert


def store_secret(name, value):
    temporary = ROOT / 'secret-upload.json'
    write(temporary, json.dumps(value))
    try:
        secret_name = 'bower-lab/' + RUN + '/' + name
        try:
            aws('secretsmanager', 'create-secret', '--name', secret_name,
                '--secret-string', 'file://' + str(temporary), '--tags',
                json.dumps([{'Key':'Project','Value':'bower-lab'},{'Key':'RunId','Value':RUN}]))
        except subprocess.CalledProcessError as error:
            if 'ResourceExistsException' not in error.stderr:
                raise
            aws('secretsmanager', 'put-secret-value', '--secret-id', secret_name,
                '--secret-string', 'file://' + str(temporary))
    finally:
        temporary.unlink(missing_ok=True)


def main():
    os.umask(0o077)
    if (ROOT/'setup-complete').exists():
        print(json.dumps({'phase':'control-setup','status':'already-complete'}))
        return
    manifest = json.loads((ROOT/'manifest.json').read_text())
    if manifest['runId'] != RUN or aws('sts','get-caller-identity')['Account'] != manifest['account']:
        raise ValueError('Lab identity mismatch')
    for filename, digest in manifest['files'].items():
        if Path(filename).name != filename:
            raise ValueError('Invalid artifact name')
        destination = ROOT / filename
        run('aws','--region',REGION,'s3','cp','s3://'+BUCKET+'/artifacts/'+filename,str(destination),'--only-show-errors')
        if hashlib.sha256(destination.read_bytes()).hexdigest() != digest:
            raise ValueError('Artifact checksum mismatch: ' + filename)
    run('dnf','install','-y','nginx','openssl')
    for archive, destination in [('management.tar.gz','/opt/bower-management'),('cli.tar.gz',str(ROOT/'cli')),('lab-pack.tar.gz',str(ROOT/'lab-pack'))]:
        Path(destination).mkdir(parents=True,exist_ok=True)
        with tarfile.open(ROOT/archive) as stream:
            for entry in stream.getmembers():
                if entry.name.startswith('/') or '..' in Path(entry.name).parts or not (entry.isfile() or entry.isdir()):
                    raise ValueError('Unsafe artifact archive entry')
            stream.extractall(destination)
    if subprocess.run(['id','bower-management'],capture_output=True).returncode:
        run('useradd','--system','--home-dir','/var/lib/bower-management','--shell','/usr/sbin/nologin','bower-management')
    run('install','-d','-o','bower-management','-g','bower-management','-m','0700','/var/lib/bower-management')
    run('chmod','-R','a+rX','/opt/bower-management')
    write('/etc/systemd/system/bower-management.service','''[Unit]
Description=Bower isolated lab management
After=network-online.target
[Service]
User=bower-management
WorkingDirectory=/opt/bower-management
ExecStart=/opt/bower-management/Bower.Management.Api
Environment=ASPNETCORE_ENVIRONMENT=Development
Environment=BOWER_AUTH_MODE=development
Environment=BOWER_MANAGEMENT_LISTEN_URL=http://127.0.0.1:4320
Environment=BOWER_MANAGEMENT_DB_PATH=/var/lib/bower-management/management.db
Restart=on-failure
NoNewPrivileges=true
UMask=0077
[Install]
WantedBy=multi-user.target
''',0o644)
    run('systemctl','daemon-reload')
    run('systemctl','enable','--now','bower-management')
    for attempt in range(60):
        try:
            api('/health')
            break
        except Exception:
            time.sleep(1)
    else:
        raise RuntimeError('Management health did not become ready')
    (ROOT/'pki').mkdir(mode=0o700,exist_ok=True)
    if not (ROOT/'pki/ca.crt').exists():
        run('openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-days','2',
            '-subj','/CN=Bower disposable lab '+RUN,'-keyout',str(ROOT/'pki/ca.key'),'-out',str(ROOT/'pki/ca.crt'),
            '-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
    ca = (ROOT/'pki/ca.crt').read_text()
    key, cert = certificate('management','serverAuth',manifest['hosts']['Control']['ip'])
    # Only enrolment and cryptographically authenticated collector requests cross
    # this proxy. Development administrator access stays on loopback behind SSM.
    write('/etc/nginx/conf.d/bower-lab.conf','''map $http_authorization $bower_assertion {
  default 0;
  "~^Bearer bwc1\\." 1;
}
server {
  listen 443 ssl;
  server_name _;
  ssl_certificate '''+str(cert)+''';
  ssl_certificate_key '''+str(key)+''';
  ssl_protocols TLSv1.2 TLSv1.3;
  client_max_body_size 1m;
  access_log off;
  location = /api/collectors/enrol {
    limit_except POST { deny all; }
    proxy_pass http://127.0.0.1:4320;
    proxy_set_header Host localhost;
  }
  location /api/ {
    if ($bower_assertion = 0) { return 401; }
    proxy_pass http://127.0.0.1:4320;
    proxy_set_header Host localhost;
  }
  location / { return 403; }
}
''',0o600)
    run('nginx','-t')
    run('systemctl','enable','--now','nginx')
    cli=ROOT/'cli/bower'
    cli.chmod(0o700)
    if not (ROOT/'pack-key/lab.key.pem').exists():
        run(str(cli),'keys','generate','--out-dir',str(ROOT/'pack-key'),'--name','lab')
    run(str(cli),'pack','build',str(ROOT/'lab-pack'),'--key',str(ROOT/'pack-key/lab.key.pem'),'--out',str(ROOT/'signed-pack'))
    pack = next((ROOT/'signed-pack').glob('*.bowerpack'))
    run(str(cli),'pack','test',str(pack),'--trusted-key',str(ROOT/'pack-key/lab.pub.pem'))
    # Publish only signed pack and public key. Signing and TLS private keys stay local.
    for source, destination in [(pack,'windows-lab.bowerpack'),(ROOT/'pack-key/lab.pub.pem','pack.pub.pem')]:
        run('aws','--region',REGION,'s3','cp',str(source),'s3://'+BUCKET+'/runs/'+RUN+'/'+destination,'--only-show-errors')
    bundles={}
    downstreams=[]
    for host, metadata in manifest['hosts'].items():
        if host=='Control':
            continue
        collector_id=RUN+'-'+host.lower()
        key, cert=certificate(host.lower(),'serverAuth' if host=='Collector' else 'clientAuth',metadata['ip'] if host=='Collector' else None)
        token=api('/api/enrolment-tokens',{'environment':'lab','collectorId':collector_id,'reason':'Disposable AWS lab','expiresInHours':8})['token']
        bundles[host]={'collectorId':collector_id,'ca':ca,'key':key.read_text(),'certificate':cert.read_text(),
            'enrolmentToken':token,'privacyKey':base64.b64encode(secrets.token_bytes(32)).decode(),
            'pack':base64.b64encode(pack.read_bytes()).decode(),'packPublicKey':(ROOT/'pack-key/lab.pub.pem').read_text()}
        if host!='Collector':
            fingerprint=run('openssl','x509','-in',str(cert),'-noout','-fingerprint','-sha256').strip().split('=',1)[1]
            downstreams.append({'collectorId':collector_id,'certificateSha256':fingerprint})
    bundles['Collector']['downstreams']={'downstreams':downstreams}
    for host,bundle in bundles.items():
        store_secret(host,bundle)
    write(ROOT/'setup-complete',RUN+'\n')
    print(json.dumps({'phase':'control-setup','status':'passed','collectors':len(bundles),'management':'loopback-admin/TLS-collector-proxy','sentinel':'deferred'}))


if __name__=='__main__':
    try:
        main()
    except Exception as error:
        # Exception messages or subprocess stdout can include secret material.
        print(json.dumps({'phase':'control-setup','status':'failed','errorType':type(error).__name__}))
        raise SystemExit(1)
