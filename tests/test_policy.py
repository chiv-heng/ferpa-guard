"""Release policy parity using synthetic files and temporary operator state."""
import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0,str(ROOT))
from shared import pii_engine as e


def finding(severity='medium',confidence='high',name='EMAIL'):
    return dict(pattern_name=name,severity=severity,confidence=confidence,count=1,description='Synthetic finding',header_only=False,is_metadata=name in e.METADATA_PATTERNS)


class PolicyTests(unittest.TestCase):
    def test_default_matrix_is_unchanged_and_floor_is_additive(self):
        for severity in ['critical','high','medium','unknown']:
            for confidence in ['high','medium','low','unknown']:
                fs=[finding(severity,confidence)]
                baseline=e.worst_action(fs)
                for floor in ['high','critical','medium']:
                    expected='block' if floor=='medium' and confidence=='high' and severity=='medium' else baseline
                    self.assertEqual(e.evaluate_policy(fs,e.resolve_policy({'FERPA_GUARD_FLOOR':floor})),expected)

    def test_strict_nonempty_compatibility_and_no_mutation(self):
        for value,active in [('',False),('1',True),('0',True),('false',True)]:
            fs=[finding('high','low','IEP_504_FLAG')];before=copy.deepcopy(fs)
            policy=e.resolve_policy({'FERPA_GUARD_STRICT':value})
            self.assertEqual(policy.strict,active)
            self.assertEqual(e.evaluate_policy(fs,policy),'block' if active else 'log')
            self.assertEqual(fs,before)

    def test_empty_allows_at_every_valid_setting(self):
        for floor in ['high','critical','medium']:
            for strict in ['', '1']:
                self.assertEqual(e.evaluate_policy([],e.resolve_policy({'FERPA_GUARD_FLOOR':floor,'FERPA_GUARD_STRICT':strict})),'allow')

    def test_metadata_cap_is_file_local_at_all_floors(self):
        metadata=[finding('high','high','IEP_504_FLAG')]
        for floor in ['high','critical','medium']:
            policy=e.resolve_policy({'FERPA_GUARD_FLOOR':floor})
            self.assertEqual(e.evaluate_policy(metadata,policy),'warn')
            self.assertEqual(e.evaluate_policy(metadata+[finding('medium','low')],policy),'block')
            self.assertEqual(e.evaluate_policy(metadata,policy),'warn')

    def test_operational_holds_never_weaken(self):
        for name in ['SCAN_READER_UNAVAILABLE','SCAN_INCOMPLETE','POLICY_CONFIG_INVALID']:
            self.assertEqual(e.evaluate_policy([finding('medium','low',name)],e.resolve_policy({})),'block')

    def test_normalization_and_invalid_value_are_sanitized(self):
        for raw,floor in [('', 'high'),(' HIGH ','high'),('Critical','critical'),(' medium ','medium')]:
            policy=e.resolve_policy({'FERPA_GUARD_FLOOR':raw})
            self.assertEqual(policy.floor,floor);self.assertFalse(policy.policy_error)
        raw='SYNTHETIC_INVALID_CONFIG'
        policy=e.resolve_policy({'FERPA_GUARD_FLOOR':raw})
        self.assertEqual(policy.floor,'invalid');self.assertEqual(policy.policy_error,'POLICY_CONFIG_INVALID')
        self.assertEqual(e.evaluate_policy([],policy),'block')
        self.assertNotIn(raw,repr(policy))


class SurfacePolicyTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.home=self.root/'home';self.home.mkdir();self.data=self.root/'data';self.data.mkdir()
        self.env={k:v for k,v in os.environ.items() if not k.startswith(('FERPA_GUARD_','PII_GUARDIAN_'))}
        self.env['HOME']=str(self.home)
        self.environment=mock.patch.dict(os.environ,self.env,clear=True);self.environment.start();self.addCleanup(self.environment.stop)
        self.mcp=self.load('policy_mcp','cowork/mcp_server.py')
        self.report=self.load('policy_report','claude-code/pii_scan_report.py')
        self.mcp.AUDIT_LOG_PATH=self.home/'mcp-audit.log'

    def load(self,name,path):
        spec=importlib.util.spec_from_file_location(name,ROOT/path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;spec.loader.exec_module(module);return module

    def write(self,name,text):
        path=self.data/name;path.write_text(text);return path

    def hook(self,path,settings=None,tool='Read',tool_input=None):
        env=dict(self.env);env.update(settings or {})
        return subprocess.run([sys.executable,str(ROOT/'claude-code/pii_guardian.py')],input=json.dumps({'tool_name':tool,'tool_input':tool_input or {'file_path':str(path)}}),capture_output=True,text=True,env=env)

    def audits(self):
        path=self.home/'.claude/logs/ferpa-guard-audit.jsonl'
        return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []

    def test_all_surfaces_recompute_floor_per_call(self):
        path=self.write('synthetic.txt','\n'.join(['synthetic@example.invalid']*6)+'\n')
        for floor,action,code in [('high','warn',0),('medium','block',2),('critical','warn',0)]:
            config={'FERPA_GUARD_FLOOR':floor}
            with mock.patch.dict(os.environ,config):
                result=self.mcp.scan_file(str(path));batch=self.report.scan_directory(str(self.data))
            self.assertEqual(result['action'],action);self.assertEqual(result['policy']['floor'],floor)
            self.assertEqual(batch['blocked'][0]['action'],action)
            self.assertEqual(batch['action_counts'][action],1)
            self.assertEqual(self.hook(path,config).returncode,code)
            self.assertEqual(self.audits()[-1]['floor'],floor)
        self.assertIn('Findings:',self.report.format_text_report(batch))
        self.assertNotIn('BLOCKED (PII detected)',self.report.format_text_report(batch))

    def test_cross_surface_strict_values_and_metadata(self):
        path=self.write('synthetic.txt','student IEP policy\n')
        for raw,action,code in [('1','block',2),('0','block',2),('false','block',2),('','warn',0)]:
            config={'FERPA_GUARD_STRICT':raw}
            with mock.patch.dict(os.environ,config):
                remote=self.mcp.scan_file(str(path));batch=self.report.scan_directory(str(self.data))
            self.assertEqual(remote['action'],action);self.assertEqual(batch['blocked'][0]['action'],action)
            self.assertEqual(self.hook(path,config).returncode,code)
            self.assertEqual(remote['findings'][0]['confidence'],'medium')

    def test_invalid_config_blocks_without_echo_on_all_surfaces(self):
        path=self.write('synthetic.txt','SYNTHETIC PUBLIC NOTE\n');raw='SYNTHETIC_INVALID_CONFIG';config={'FERPA_GUARD_FLOOR':raw}
        with mock.patch.dict(os.environ,config):
            remote=self.mcp.scan_file(str(path));batch=self.report.scan_directory(str(self.data))
        hook=self.hook(path,config)
        self.assertIn('POLICY_CONFIG_INVALID',hook.stdout+hook.stderr)
        self.assertIn('No file contents were read',hook.stdout+hook.stderr)
        self.assertEqual(hook.returncode,2);self.assertEqual(remote['action'],'block');self.assertTrue(remote['error']);self.assertTrue(batch['errors'])
        rec=self.audits()[-1];self.assertEqual(rec['floor'],'invalid');self.assertEqual(rec['policy_error'],'POLICY_CONFIG_INVALID')
        self.assertNotIn(raw,json.dumps([remote,batch,self.audits()])+hook.stdout+hook.stderr)

    def test_full_bypass_and_scope_audits_include_policy(self):
        path=self.write('synthetic.txt','SYNTHETIC\n');config={'FERPA_GUARD_ALLOW':str(path),'FERPA_GUARD_FLOOR':'medium','FERPA_GUARD_STRICT':'0'}
        self.assertEqual(self.hook(path,config).returncode,0)
        self.assertEqual((self.audits()[-1]['floor'],self.audits()[-1]['strict']),('medium',True))
        scope={'path':str(self.data),'pattern':'synthetic','output_mode':'content'}
        self.assertEqual(self.hook(path,{'FERPA_GUARD_FLOOR':'medium'},tool='Grep',tool_input=scope).returncode,2)
        self.assertEqual(self.audits()[-1]['patterns'],['GREP_SCOPE']);self.assertEqual(self.audits()[-1]['floor'],'medium')
        with mock.patch.dict(os.environ,config):remote=self.mcp.scan_file(str(path))
        self.assertEqual(remote['action'],'allow');self.assertEqual(remote['policy']['floor'],'medium')

    def test_empty_mcp_has_policy_and_audit(self):
        path=self.write('empty.txt','')
        with mock.patch.dict(os.environ,{'FERPA_GUARD_FLOOR':'medium'}):remote=self.mcp.scan_file(str(path))
        self.assertEqual(remote['action'],'allow');self.assertEqual(remote['policy']['floor'],'medium')
        self.assertIn('floor=medium',(self.home/'mcp-audit.log').read_text())

    def test_missing_dependency_shared_hold_and_redact_unchanged(self):
        path=self.write('synthetic.xlsx','SYNTHETIC')
        with mock.patch.dict(sys.modules,{'openpyxl':None}):
            remote=self.mcp.scan_file(str(path));redact=self.mcp.redact_file(str(path))
        self.assertEqual(remote['action'],'block');self.assertEqual(remote['reader_error'],'MISSING_DEPENDENCY:openpyxl')
        self.assertTrue(redact['error'])

    def test_strict_cache_transition_preserves_raw_confidence(self):
        path=self.write('synthetic.txt','student IEP policy\n')
        for config,expected in [({},0),({'FERPA_GUARD_STRICT':'1'},2),({},0)]:
            self.assertEqual(self.hook(path,dict(config,FERPA_GUARD_CACHE='1')).returncode,expected)
            cache=json.loads((self.home/'.claude/ferpa-guard-cache.json').read_text())
            self.assertEqual(cache['version'],8)
            self.assertEqual(cache['entries'][0]['findings'][0]['confidence'],'medium')

    def test_warm_cache_default_medium_strict_default_has_no_policy_payload(self):
        path=self.write('synthetic.txt','\n'.join(['synthetic@example.invalid']*6)+'\n')
        for config,expected in [({},0),({'FERPA_GUARD_FLOOR':'medium'},2),({'FERPA_GUARD_STRICT':'1'},2),({},0)]:
            self.assertEqual(self.hook(path,dict(config,FERPA_GUARD_CACHE='1')).returncode,expected)
            cache=json.loads((self.home/'.claude/ferpa-guard-cache.json').read_text())
            fs=cache['entries'][0]['findings']
            self.assertEqual(fs[0]['confidence'],'high')
            for f in fs:
                self.assertFalse({'action','floor','strict','policy'} & f.keys())

    def test_report_reader_exception_is_sanitized_and_counted(self):
        self.write('synthetic.txt','SYNTHETIC')
        with mock.patch.object(self.report,'read_file_content',side_effect=ValueError('SYNTHETIC_EXCEPTION_SENTINEL')):
            result=self.report.scan_directory(str(self.data))
        self.assertEqual(result['action_counts']['block'],1)
        self.assertEqual(len(result['actions']),1)
        self.assertNotIn('SYNTHETIC_EXCEPTION_SENTINEL',json.dumps(result))

    def test_audit_io_failure_does_not_change_policy_action(self):
        path=self.write('synthetic.txt','student IEP policy\n')
        with mock.patch.object(Path,'open',side_effect=OSError('SYNTHETIC')):
            e.write_audit_event(self.home/'audit.jsonl','block',str(path),['IEP_504_FLAG'],floor='medium',strict=True)
        self.assertEqual(e.evaluate_policy([finding('high','medium','IEP_504_FLAG')],e.resolve_policy({'FERPA_GUARD_STRICT':'1'})),'block')

    def test_hard_denial_stays_unaudited_and_exemptions_survive_invalid_floor(self):
        path=self.write('synthetic.txt','SYNTHETIC')
        self.assertEqual(self.hook(path,{'FERPA_GUARD_HARD_DENY':str(self.data),'FERPA_GUARD_FLOOR':'invalid'}).returncode,2)
        self.assertEqual(self.audits(),[])
        exempt=self.write('README.md','SYNTHETIC')
        self.assertEqual(self.hook(exempt,{'FERPA_GUARD_FLOOR':'invalid'}).returncode,0)

    def test_report_warn_remains_diagnostic_nonzero(self):
        self.write('synthetic.txt','\n'.join(['synthetic@example.invalid']*6)+'\n')
        proc=subprocess.run([sys.executable,str(ROOT/'claude-code/pii_scan_report.py'),str(self.data),'--json'],capture_output=True,text=True,env=self.env)
        self.assertNotEqual(proc.returncode,0)
        self.assertEqual(json.loads(proc.stdout)['action_counts']['warn'],1)


if __name__=='__main__':unittest.main()
