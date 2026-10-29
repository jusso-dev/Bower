import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from cleanup import verify_secret
from lab import verify_stack
from ssm import verify_host

class GuardTests(unittest.TestCase):
    def test_secret_requires_exact_name_and_both_tags(self):
        secret={'Name':'bower-lab/run/Collector','Tags':[{'Key':'Project','Value':'bower-lab'},{'Key':'RunId','Value':'run'}]}
        verify_secret(secret,'run')
        for invalid in ({**secret,'Name':'bower-lab/run-other/Collector'},{**secret,'Name':'bower-lab/run/customer'},{**secret,'Tags':[]},{**secret,'Name':'bower-lab/run/Collector/extra'}):
            with self.assertRaises(ValueError):verify_secret(invalid,'run')
    def test_stack_and_running_host_must_belong_to_run(self):
        tags=[{'Key':'Project','Value':'bower-lab'},{'Key':'RunId','Value':'run'}]
        verify_stack({'Tags':tags},'run')
        verify_host({'Tags':tags,'State':{'Name':'running'}},{'runId':'run'})
        with self.assertRaises(ValueError):verify_stack({'Tags':tags},'other')
        with self.assertRaises(ValueError):verify_host({'Tags':tags,'State':{'Name':'stopped'}},{'runId':'run'})
        with self.assertRaises(ValueError):verify_host({'Tags':[],'State':{'Name':'running'}},{'runId':'run'})
if __name__=='__main__':unittest.main()
