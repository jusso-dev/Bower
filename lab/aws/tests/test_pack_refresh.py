"""Exercise the deployed refresh script with an isolated control-host double."""
import base64
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import sys
import tarfile
import tempfile
from types import SimpleNamespace
import unittest
from unittest.mock import patch
from contextlib import redirect_stdout

SCRIPTS=Path(__file__).resolve().parents[1]/'scripts'
sys.path.insert(0,str(SCRIPTS))
spec=importlib.util.spec_from_file_location('stage_receipts',SCRIPTS/'stage-receipts.py')
stage=importlib.util.module_from_spec(spec)
spec.loader.exec_module(stage)


class ReceiptTimingTests(unittest.TestCase):
    def test_crash_cutoff_is_attached_without_changing_other_receipts(self):
        receipts=[['Collector','crash.acks.json',{'acknowledged':['id']}],['Linux1','smoke.acks.json',{'acknowledged':['other']}]]
        stage.attach_deadlines(receipts,{'Collector':{'crashedAtUnix':1000,'recoveryDeadlineSeconds':120}})
        self.assertEqual(1120,receipts[0][2]['recoveryDeadlineUnix'])
        self.assertNotIn('recoveryDeadlineUnix',receipts[1][2])
        for timing in ({},{'crashedAtUnix':float('nan'),'recoveryDeadlineSeconds':120},{'crashedAtUnix':1000,'recoveryDeadlineSeconds':300}):
            with self.assertRaises(ValueError):stage.attach_deadlines(receipts,{'Collector':timing})


class PackRefreshTests(unittest.TestCase):
    def execute_refresh(self,root,count):
        archive=root/'lab-pack.tar.gz'
        with tarfile.open(archive,'w:gz') as stream:
            data=b'version: 1.0.1\n';info=tarfile.TarInfo('pack.yaml');info.size=len(data)
            stream.addfile(info,io.BytesIO(data))
        (root/'manifest.json').write_text(json.dumps({'runId':'fixture','account':'fixture','files':{'lab-pack.tar.gz':hashlib.sha256(archive.read_bytes()).hexdigest()},'hosts':['Control','Collector']}))
        (root/'signed-pack').mkdir()
        (root/'signed-pack/windows-lab-1.0.0.bowerpack').write_bytes(b'stale')
        stored=[];tested=[]
        def run(*args):
            if args[2]=='build':
                output=Path(args[args.index('--out')+1]);output.mkdir()
                for index in range(count):(output/f'windows-lab-1.0.{index+1}.bowerpack').write_bytes(b'fresh')
            elif args[2]=='test':tested.append(Path(args[3]).read_bytes())
            else:raise AssertionError(args)
        def aws(*args):
            if args[0]=='sts':return {'Account':'fixture'}
            return {'SecretString':json.dumps({'preserved':'metadata'})}
        control=SimpleNamespace(ROOT=root,RUN='fixture',aws=aws,run=run,store_secret=lambda host,bundle:stored.append((host,bundle)),write=lambda path,value:path.write_text(value))
        script=(SCRIPTS/'refresh-pack.sh').read_text().split("python3 - <<'PY'\n",1)[1].rsplit('\nPY',1)[0]
        with patch.dict(sys.modules,{'control':control}),redirect_stdout(io.StringIO()):exec(compile(script,'refresh-pack.sh','exec'),{})
        return stored,tested

    def test_version_bump_distributes_only_fresh_build_and_cleans_up(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);stored,tested=self.execute_refresh(root,1)
            self.assertEqual([b'fresh'],tested)
            self.assertEqual(b'fresh',base64.b64decode(stored[0][1]['pack']))
            self.assertEqual('metadata',stored[0][1]['preserved'])
            self.assertEqual([],list(root.glob('pack-refresh-*')))

    def test_missing_or_ambiguous_build_never_falls_back_to_stale_pack(self):
        for count in (0,2):
            with tempfile.TemporaryDirectory() as folder:
                root=Path(folder)
                with self.assertRaisesRegex(SystemExit,'exactly one'):self.execute_refresh(root,count)
                self.assertFalse((root/'setup-complete').exists())
                self.assertEqual([],list(root.glob('pack-refresh-*')))


if __name__=='__main__':unittest.main()
