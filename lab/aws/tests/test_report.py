"""Score passing and failing campaigns without inheriting the first run's conclusions."""
import json
from pathlib import Path
import sys
import tempfile
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
import report


class ReportTests(unittest.TestCase):
    def fixtures(self,root):
        rows=[{'host':host,'phase':'crash.acks.json','expected':1,'missing':0,'duplicates':0,'deniedInOutput':0} for host in ('Collector','Linux1','Linux2')]
        final={'receipts':rows,'duplicateOutputEvents':0,'rawSeedHits':{},'persistedRawSeedHits':{},'serviceLogRawSeedHits':{},'outputRows':3,'uniqueEvents':3,'positiveControls':3,'detectedLabels':{}}
        metadata=[{'metadata':[{'phase':'post-reboot','host':host,'health':'healthy','bootToProcessSeconds':30}]} for host in ('Linux2','Wec','Windows1','Windows2')]
        metadata.extend({'metadata':[{'phase':'ledger','host':host,'intact':True}]} for host in ('Wec','Windows1','Windows2'))
        files={'verification/final-drained-verification.json':final,'verification/final-verification.json':{'receipts':rows},'verification/baseline-drained-verification.json':{'outputLatencyP95Seconds':10},'P0/fleet.json':{'negativeAuth':{'anonymous-admin':401,'invalid-assertion':401,'remote-dashboard':403},'status':'passed'},'ssm-metadata.json':metadata,'hosts/Collector/outage-recovery.json':{'recoverySeconds':15,'status':'passed'},'hosts/Collector/disk.json':{'httpStatuses':{'503':100},'status':'passed'},'hosts/Collector/replay.json':{'first':202,'identical':200,'conflicting':409,'status':'passed'},'cleanup.json':{'status':'passed'},'dashboard-browser.json':{}}
        for host in ('Collector','Linux1','Linux2'):
            files['hosts/'+host+'/ledger.json']={'intact':True}
            files['hosts/'+host+'/crash-recovery.json']={'healthy':True,'recoverySeconds':5}
            files['hosts/'+host+'/resources.json']=[{'memoryUsedPercent':20,'loadAverage':[1],'diskAvailableBytes':1024}]
        for host in ('Linux1','Linux2'):
            for phase in ('load1k','load5k'):
                files['hosts/'+host+'/'+phase+'.json']={'acknowledged':300000,'acknowledgedEps':5000}
        for name,data in files.items():
            p=root/name;p.parent.mkdir(parents=True,exist_ok=True);p.write_text(json.dumps(data))
        return {'runId':'fixture','region':'test-region','windowsFallback':{'observed':True},'cpuCredits':'unlimited','outputs':{'Bucket':'fixture'}},{'version':'fixture','sourceCommit':'fixture','artifactCommit':'fixture','artifactRun':1,'files':{}},{'normalOutputP95LatencySeconds':60,'recoveryDeadlineSeconds':120}

    def test_healthy_linux_reboot_does_not_pollute_windows_result(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);state,manifest,thresholds=self.fixtures(root)
            result=report.build(root,state,manifest,thresholds)
        self.assertEqual({'Wec','Windows1','Windows2'},set(result['windowsReboot']))
        self.assertEqual('passed',result['status'])
        self.assertEqual([],result['findings'])
        self.assertIn('All measured claims passed.',report.summary(result))
        self.assertNotIn('deadlines failed','\n'.join(report.markdown_lines(result)))
        self.assertTrue(all(step['status']=='exploratory-target-met' for step in result['load']))
        delayed=next(c for c in result['claims'] if c['claim'].startswith('Acknowledged events still'))
        self.assertIn('0 acknowledged',delayed['scope'])
        self.assertNotIn('Two central',delayed['scope'])

    def test_failure_prose_names_the_actual_failure(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);state,manifest,thresholds=self.fixtures(root)
            p=root/'verification/final-drained-verification.json';v=json.loads(p.read_text());v['rawSeedHits']={'fixture':1};p.write_text(json.dumps(v))
            result=report.build(root,state,manifest,thresholds)
        self.assertEqual('failed',result['status'])
        self.assertIn('Raw synthetic seed leaks',report.summary(result))
        self.assertNotIn('latency',report.summary(result))

    def test_missing_windows_timing_cannot_pass(self):
        with tempfile.TemporaryDirectory() as folder:
            root=Path(folder);state,manifest,thresholds=self.fixtures(root)
            p=root/'ssm-metadata.json';metadata=json.loads(p.read_text())
            metadata[1]['metadata'][0].pop('bootToProcessSeconds')
            p.write_text(json.dumps(metadata))
            result=report.build(root,state,manifest,thresholds)
        claim=next(c for c in result['claims'] if c['claim']=='Windows boot-to-process seconds')
        self.assertEqual('failed',claim['status'])
        self.assertIsNone(claim['measured'])

if __name__=='__main__':unittest.main()
