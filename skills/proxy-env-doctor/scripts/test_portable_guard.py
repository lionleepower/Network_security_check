import copy
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import time
import unittest
from unittest.mock import patch
from guard_config import validate
from guard_lifecycle import initialize, candidate, wrapper, prepare, install, uninstall, discover
from guard_store import save
from portable_guard import PortableGuard
from browser_pause_latch import pause, resume
from test_browser_pause_latch import FakeNative
from test_ippure_guard import Fake
from parse_ippure import EXPECTED
from leak_policy import BASELINE_URL


def configured(directory):
    initialize(directory)
    c=json.loads((directory/'config.json').read_text(encoding='utf-8'))
    c.update(status='ready',region='JP',broadband_ips=['198.51.100.9'],baseline_source='offline-fixture')
    c['authorization']={k:True for k in c['authorization']}
    c['browser'].update(extension_instance='fixture-browser',proxy='http://127.0.0.1:29181')
    c['controller'].update(controller='http://127.0.0.1:29180')
    c['routing'].update(group='Fixture-Guard',fallback='Fixture-Fallback',probe_group='Fixture-Probe',
                        inbound='fixture-entry',probe_inbound='fixture-probe',port=29181,probe_port=29182,nodes=['JP-A','JP-B'])
    c['node_runtime']=str(Path(shutil.which('node') or '/missing/node').resolve())
    save(directory/'config.json',c)
    return c


class RegionAdapter(Fake):
    def route(self,action,**data):
        if action=='switch':
            self.calls.append(action)
            return {'kind':'switch_receipt','success':True,'node':'JP-B','country':'JP','exit_ip':'203.0.113.22','observed_at':time.time()}
        return super().route(action,**data)


class PortableTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.directory=self.root/'private'
        self.c=configured(self.directory)

    def event(self,value='198.51.100.9'):
        return {'source':'live-browser','url':BASELINE_URL,'extension_instance':'fixture-browser',
                'observed_at':time.time(),'proxy_exit':'203.0.113.11',
                'rows':[{'server':f'stun:{h}:{p}','result':value} for h,p in EXPECTED]}

    def test_draft_never_enables(self):
        directory=self.root/'draft';initialize(directory)
        c=json.loads((directory/'config.json').read_text())
        self.assertFalse(any(c['authorization'].values()))
        self.assertFalse(json.loads((directory/'state.json').read_text())['enabled'])
        with self.assertRaises(ValueError):PortableGuard(directory)

    def test_config_rejects_remote_controller_duplicate_ports_missing_scope(self):
        for key,value in [('remote',None),('ports',None),('region',None)]:
            c=copy.deepcopy(self.c)
            if key=='remote':c['controller']['controller']='http://example.com:9090'
            if key=='ports':c['routing']['probe_port']=c['routing']['port']
            if key=='region':c['region']=None
            with self.assertRaises(ValueError):validate(c)
        (Path(self.c['browser']['profile'])/'.proxy-env-doctor-scope.json').unlink()
        with self.assertRaises(OSError):validate(self.c,check_files=True)

    def test_non_singapore_complete_incident(self):
        adapter=RegionAdapter();guard=PortableGuard(self.directory,adapter,check_files=False)
        guard.enable()
        self.assertEqual(guard.ingest(self.event())['phase'],'rechecking')
        self.assertEqual(guard.ingest(self.event())['phase'],'suspend_required')
        self.assertEqual(adapter.calls.count('switch'),1)
        guard.manual_resume();self.assertFalse(guard.state['enabled'])

    def test_zero_candidates_never_switch(self):
        adapter=RegionAdapter();guard=PortableGuard(self.directory,adapter,check_files=False);guard.enable()
        self.assertEqual(guard.ingest(self.event('未检测到WebRTC IP泄露'))['action'],'observation_unknown')
        self.assertNotIn('switch',adapter.calls)

    def test_custom_profile_and_port_scope(self):
        profile=Path(self.c['browser']['profile']);b=self.c['browser']
        rows=[{'pid':1,'parent':0,'created':100,'name':'msedge.exe','command':f'edge --user-data-dir="{profile}" --proxy-server={b["proxy"]}'},
              {'pid':2,'parent':1,'created':200,'name':'msedge.exe','command':''},
              {'pid':3,'parent':0,'created':300,'name':'msedge.exe','command':'edge --user-data-dir="other" --proxy-server=http://127.0.0.1:29181'}]
        native=FakeNative();scan=lambda p:rows;journal=self.directory/'pause.json'
        pause(profile,journal,native,scan,scope=b)
        self.assertEqual(native.paused,[1,2])
        resume(journal,native,scan)
        self.assertEqual(native.resumed,[2,1])

    def test_marker_cannot_be_replaced(self):
        b=self.c['browser'];save(Path(b['profile'])/'.proxy-env-doctor-scope.json',{'scope_id':'different'})
        with self.assertRaises(ValueError):pause(Path(b['profile']),self.directory/'pause.json',FakeNative(),lambda p:[],scope=b)

    def test_ipv6_proxy_cannot_mismatch_ipv4_listener(self):
        self.c['browser']['proxy']='http://[::1]:29181'
        with self.assertRaises(ValueError):validate(self.c)


class DeploymentTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup)
        self.root=Path(self.tmp.name);self.directory=self.root/'private';self.c=configured(self.directory)
        self.source={'mode':'global','mixed-port':29000,'proxies':[{'name':'JP-A','type':'ss','server':'192.0.2.1'},{'name':'JP-B','type':'ss','server':'192.0.2.2'}], 'proxy-groups':[{'name':'Existing','type':'select','proxies':['JP-A']}], 'rules':['MATCH,Existing']}

    def test_preserves_source_and_rejects_collision_or_hidden_chain(self):
        before=copy.deepcopy(self.source);out=candidate(self.source,self.c)
        self.assertEqual(self.source,before);self.assertEqual(out['rules'],before['rules'])
        for key in ('port','dialer','name'):
            source=copy.deepcopy(self.source)
            if key=='port':source['mixed-port']=29181
            if key=='dialer':source['proxies'][0]['dialer-proxy']='DIRECT'
            if key=='name':source['proxy-groups'][0]['name']='Fixture-Guard'
            with self.assertRaises(ValueError):candidate(source,self.c)

    def test_discovery_omits_credentials_and_marks_unverified(self):
        import yaml
        source=copy.deepcopy(self.source);source['secret']='fixture-secret';source['proxies'][0]['password']='fixture-password'
        file=self.root/'source.yaml';file.write_text(yaml.safe_dump(source),encoding='utf-8')
        discover(file,self.directory/'discovery.json')
        text=(self.directory/'discovery.json').read_text()
        self.assertNotIn('fixture-secret',text);self.assertNotIn('fixture-password',text)
        self.assertIn('not_runtime',text)

    def test_generated_extension_matches_prepared_yaml(self):
        script=wrapper('function main(config){return config;}',self.c)
        invocation=script+'\nconsole.log(JSON.stringify(main('+json.dumps(self.source)+')));'
        result=subprocess.run([self.c['node_runtime'],'-e',invocation],capture_output=True,encoding='utf-8',check=True)
        self.assertEqual(json.loads(result.stdout),candidate(self.source,self.c))

    def prepared(self):
        import yaml
        client=self.root/'client';client.mkdir()
        source=client/'runtime.yaml';source.write_text(yaml.safe_dump(self.source),encoding='utf-8')
        extension=client/'profile.js';extension.write_text('function main(config){return config;}',encoding='utf-8')
        core=client/'core-fixture';core.write_bytes(b'Offline test binary placeholder, never executed')
        with patch('guard_lifecycle.subprocess.run') as command:
            result=prepare(self.directory,source,extension,core,client)
            self.assertEqual(command.call_count,2)
        self.assertTrue(result['prepared'])
        return source,extension

    def test_install_uninstall_preserves_later_global_choice(self):
        source,extension=self.prepared();original=source.read_bytes()
        class Adapter:
            selection='Existing'
            def route(this,action,**data):
                if action=='snapshot':return {'mode':'global','selectors':{'GLOBAL':this.selection,'Existing':'JP-A'}}
                if action=='inspect':return {'verified':True}
                return {}
        adapter=Adapter()
        with patch('guard_lifecycle.socket.socket'):
            self.assertTrue(install(self.directory,adapter)['installed'])
        adapter.selection='JP-B'
        self.assertTrue(uninstall(self.directory,adapter)['uninstalled'])
        self.assertEqual(source.read_bytes(),original)
        self.assertEqual(json.loads((self.directory/'selectors.json').read_text())['selectors']['GLOBAL'],'JP-B')
        self.assertTrue(Path(self.c['browser']['profile']).exists())

    def test_operator_edits_block_uninstall(self):
        source,_=self.prepared()
        m=json.loads((self.directory/'deployment.json').read_text());m['phase']='installed';save(self.directory/'deployment.json',m)
        source.write_text('operator later change')
        with self.assertRaises(ValueError):uninstall(self.directory,object())
        self.assertEqual(source.read_text(),'operator later change')

    def test_failed_install_rolls_back(self):
        source,extension=self.prepared();before=source.read_bytes()
        class Adapter:
            def route(this,action,**data):
                if action=='snapshot':return {'mode':'global','selectors':{'GLOBAL':'Existing'}}
                if action=='inspect':raise OSError('simulated runtime error')
                return {}
        with patch('guard_lifecycle.socket.socket'):
            with self.assertRaises(OSError):install(self.directory,Adapter())
        self.assertEqual(source.read_bytes(),before)
        self.assertEqual(json.loads((self.directory/'deployment.json').read_text())['phase'],'rolled_back')


if __name__=='__main__':unittest.main()
