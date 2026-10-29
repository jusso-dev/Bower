"""Install/configure a Linux node. All secret handling stays in memory or owner-only files."""
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import time
import urllib.request

ROOT=Path('/opt/bower-lab')
RUN=os.environ['BOWER_LAB_RUN']
HOST=os.environ['BOWER_LAB_HOST']
REGION=os.environ['AWS_DEFAULT_REGION']
BUCKET=os.environ['BOWER_LAB_BUCKET']


def run(*args):
    return subprocess.run(args,check=True,capture_output=True,text=True).stdout


def aws(*args):
    out=run('aws','--region',REGION,*args,'--output','json')
    return json.loads(out) if out.strip() else {}


def write(path,value,mode=0o640,owner='root',group='bower'):
    path=Path(path)
    path.parent.mkdir(parents=True,exist_ok=True)
    path.write_bytes(value if isinstance(value,bytes) else value.encode())
    path.chmod(mode)
    shutil.chown(path,user=owner,group=group)


def main():
    os.umask(0o077)
    if HOST not in ('Collector','Linux1','Linux2'):
        raise ValueError('Wrong host platform')
    manifest=json.loads((ROOT/'manifest.json').read_text())
    if manifest['runId']!=RUN or aws('sts','get-caller-identity')['Account']!=manifest['account']:
        raise ValueError('Lab identity mismatch')
    package=ROOT/'collector.rpm'
    run('aws','--region',REGION,'s3','cp','s3://'+BUCKET+'/artifacts/collector.rpm',str(package),'--only-show-errors')
    if hashlib.sha256(package.read_bytes()).hexdigest()!=manifest['files']['collector.rpm']:
        raise ValueError('Package checksum mismatch')
    run('dnf','install','-y',str(package))
    run('systemctl','stop','bower')
    if HOST=='Collector' and not Path('/var/lib/bower/.lab-volume').exists():
        devices=json.loads(run('lsblk','--json','--bytes','--output','NAME,SIZE,TYPE,MOUNTPOINT,FSTYPE'))['blockdevices']
        candidates=[d for d in devices if d['type']=='disk' and int(d['size'])==4*1024**3 and not d.get('mountpoint') and not d.get('children')]
        if len(candidates)!=1 or candidates[0].get('fstype'):
            raise ValueError('Expected one fresh, unmounted 4GiB queue disk')
        device='/dev/'+candidates[0]['name']
        run('mkfs.ext4','-q',device)
        run('mount',device,'/var/lib/bower')
        uuid=run('blkid','-s','UUID','-o','value',device).strip()
        with Path('/etc/fstab').open('a') as stream:
            stream.write('UUID='+uuid+' /var/lib/bower ext4 defaults,nofail 0 2\n')
        Path('/var/lib/bower/.lab-volume').touch()
    for path in ('/var/lib/bower','/var/lib/bower/enrolment','/var/lib/bower/spool'):
        run('install','-d','-o','bower','-g','bower','-m','0700',path)
    for path in ('/etc/bower/secrets','/etc/bower/keys','/etc/bower/packs'):
        run('install','-d','-o','root','-g','bower','-m','0750',path)
    bundle=json.loads(aws('secretsmanager','get-secret-value','--secret-id','bower-lab/'+RUN+'/'+HOST)['SecretString'])
    write('/etc/bower/keys/ca.pem',bundle['ca'])
    write('/etc/bower/secrets/client.key',bundle['key'])
    write('/etc/bower/secrets/client.crt',bundle['certificate'])
    write('/etc/bower/secrets/privacy.key',base64.b64decode(bundle['privacyKey']))
    if not Path('/var/lib/bower/management-credential/credential.json').exists():
        write('/var/lib/bower/enrolment/enrolment-token',bundle['enrolmentToken'],0o600,'bower')
    common={
        'BOWER_COLLECTOR_ID':bundle['collectorId'],'BOWER_ENVIRONMENT':'lab',
        'BOWER_MANAGEMENT_ENDPOINT':'https://'+manifest['hosts']['Control']['ip']+'/',
        'BOWER_MANAGEMENT_AUTH':'enrolment','BOWER_MANAGEMENT_CA_BUNDLE':'/etc/bower/keys/ca.pem',
        'BOWER_MANAGEMENT_ENROLMENT_TOKEN_FILE':'/var/lib/bower/enrolment/enrolment-token',
        'BOWER_MANAGEMENT_ENROLMENT_TOKEN_REMOVE_AFTER_USE':'true',
        'BOWER_PRIVACY_HMAC_KEY_FILE':'/etc/bower/secrets/privacy.key',
        'BOWER_QUEUE_PATH':'/var/lib/bower/queue.db','BOWER_QUEUE_MAX_BYTES':str(1024**3),
        'BOWER_INGEST_RATE_PER_SECOND':'6000','BOWER_PRODUCER_SCOPES_FILE':'/etc/bower/producer-scopes.json',
    }
    write('/etc/bower/producer-scopes.json',json.dumps([{'producer':'anonymous','application':{'name':'BowerLab','environment':'lab'},'source':{'ipAddress':'192.0.2.10'}}]))
    if HOST=='Collector':
        common.update({'BOWER_LISTEN_URL':'http://127.0.0.1:4318','BOWER_OUTPUT':'ama-spool',
            'BOWER_AMA_SPOOL_PATH':'/var/lib/bower/spool','BOWER_RELAY_LISTEN_URL':'https://0.0.0.0:4319',
            'BOWER_RELAY_CERTIFICATE_FILE':'/etc/bower/secrets/client.crt','BOWER_RELAY_KEY_FILE':'/etc/bower/secrets/client.key',
            'BOWER_RELAY_DOWNSTREAMS_FILE':'/etc/bower/downstreams.json'})
        write('/etc/bower/downstreams.json',json.dumps(bundle['downstreams']))
    else:
        common.update({'BOWER_LISTEN_URL':'http://127.0.0.1:4319','BOWER_OUTPUT':'relay',
            'BOWER_RELAY_URL':'https://'+manifest['hosts']['Collector']['ip']+':4319',
            'BOWER_RELAY_CLIENT_CERTIFICATE_FILE':'/etc/bower/secrets/client.crt',
            'BOWER_RELAY_CLIENT_KEY_FILE':'/etc/bower/secrets/client.key','BOWER_RELAY_CA_BUNDLE':'/etc/bower/keys/ca.pem'})
    write('/etc/bower/bower.env',''.join(k+'='+v+'\n' for k,v in common.items()))
    # Lab secrets must never appear in a core dump during fault injection.
    write('/etc/systemd/system/bower.service.d/lab.conf','[Service]\nLimitCORE=0\n',0o644,'root','root')
    run('systemctl','daemon-reload')
    run('systemctl','restart','bower')
    port=4318 if HOST=='Collector' else 4319
    for attempt in range(60):
        try:
            with urllib.request.urlopen('http://127.0.0.1:'+str(port)+'/health',timeout=2) as response:
                if response.status==200:
                    break
        except Exception:
            time.sleep(1)
    else:
        raise RuntimeError('Collector health failed')
    print(json.dumps({'phase':'install','host':HOST,'status':'passed','packageSha256':manifest['files']['collector.rpm'],
        'serviceUser':run('systemctl','show','bower','--property','User','--value').strip(),'signedPackage':False,'output':common['BOWER_OUTPUT']}))


if __name__=='__main__':
    try:
        main()
    except Exception as error:
        print(json.dumps({'phase':'install','host':HOST,'status':'failed','errorType':type(error).__name__}))
        raise SystemExit(1)
