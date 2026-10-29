import sys
from pathlib import Path
import unittest
sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'scripts'))
from lab import record_observations

class StateTests(unittest.TestCase):
    def test_status_records_observed_sizes_and_credit_modes(self):
        hosts=('Control','Collector','Linux1','Linux2','Wec','Windows1','Windows2')
        state={'outputs':{host+'Id':'id-'+host for host in hosts}}
        instances=[{'InstanceId':'id-'+host,'InstanceType':'t3.small' if host=='Wec' else 't3.micro'} for host in hosts]
        credits=[{'InstanceId':'id-'+host,'CpuCredits':'standard' if host=='Linux1' else 'unlimited'} for host in hosts]
        record_observations(state,instances,credits,'Measured memory exceeded 90%')
        self.assertEqual(['Wec'],state['windowsFallback']['hosts'])
        self.assertEqual('mixed',state['windowsFallback']['finalType'])
        self.assertEqual('t3.small',state['windowsFallback']['finalTypes']['Wec'])
        self.assertEqual('mixed',state['cpuCredits'])
        self.assertEqual('standard',state['observedCpuCredits']['Linux1'])
        record_observations(state,instances,credits)
        self.assertEqual('Measured memory exceeded 90%',state['windowsFallback']['reason'])
        state['windowsFallback']={'observed':False,'reason':'Not yet observed'}
        record_observations(state,instances,credits)
        self.assertEqual('Resize observed; reason not recorded',state['windowsFallback']['reason'])
        with self.assertRaises(ValueError):record_observations(state,instances,credits[:-1])

if __name__=='__main__':unittest.main()
