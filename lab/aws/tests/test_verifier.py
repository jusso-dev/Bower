import importlib.util
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch
from collections import Counter

with patch.dict(os.environ, {'BOWER_LAB_RUN':'test','BOWER_LAB_BUCKET':'test','BOWER_LAB_HOST':'Collector','AWS_DEFAULT_REGION':'ap-southeast-2'}):
    spec=importlib.util.spec_from_file_location('lab_verify',Path(__file__).resolve().parents[1]/'scripts/verify.py')
    verify=importlib.util.module_from_spec(spec)
    spec.loader.exec_module(verify)

class VerifierTests(unittest.TestCase):
    def test_privacy_alert_is_not_a_duplicate_source_event(self):
        source={'eventId':'native-1','eventType':'authentication_failure','request':{'correlationId':'source-1'},'timeGenerated':'2026-10-29T07:49:28.27455+00:00','eventOutcomeReason':'synthetic-seed','privacy':{'detected':['id.email']}}
        alert={**source,'eventId':'privacy-1','eventType':'sensitive_data_detected','eventOutcomeReason':'redacted','timeGenerated':'2026-10-29T07:49:28.2745512+00:00'}
        corpus={'values':{'test':'synthetic-seed'},'positiveControl':'canary'}
        with tempfile.TemporaryDirectory() as folder:
            path=Path(folder);(path/'events.jsonl').write_text('\n'.join(json.dumps(e) for e in (source,alert)))
            with patch.object(verify,'Path',return_value=path),patch.object(verify,'aws',return_value={'SecretString':json.dumps(corpus)}):
                events,correlations,_,_,_,latencies,leaks,_=verify.snapshot()
        self.assertEqual(2,len(events));self.assertEqual(1,correlations['source-1'])
        self.assertEqual(1,leaks['test']);self.assertEqual(2,len(latencies))

    def test_empty_or_malformed_source_receipts_cannot_pass_coverage(self):
        receipts=[(host,'phase',{'acknowledged':[host]}) for host in ('Collector','Linux1','Linux2','Wec','Windows1','Windows2')]
        verify.validate_receipts(receipts)
        for bad in ([],receipts[:-1],receipts[:-1]+[('Windows2','phase',{'acknowledged':[]})],receipts[:-1]+[('Windows2','native',{'correlations':['x'],'written':2})]):
            with self.assertRaises(ValueError):verify.validate_receipts(bad)

    def test_missing_duplicate_and_denied_receipts_fail(self):
        receipts=[('host','phase',{'acknowledged':['a','b'],'denied':['denied']})]
        for counts in ({'a':1},{'a':2,'b':1},{'a':1,'b':1,'denied':1}):
            events=Counter(counts);rows=verify.receipt_summary(receipts,events,Counter())
            self.assertFalse(verify.consistency_passed(rows,events,True,{}))
        events=Counter({'a':1,'b':1});rows=verify.receipt_summary(receipts,events,Counter())
        self.assertTrue(verify.consistency_passed(rows,events,True,{}))
        self.assertFalse(verify.consistency_passed(rows,events,False,{}))
        self.assertFalse(verify.consistency_passed(rows,events,True,{'seed':1}))
        self.assertFalse(verify.consistency_passed([],events,True,{}))

if __name__=='__main__':unittest.main()
