import io
import json
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch
import native_ippure_service as service
from ippure_guard import Adapter


class Child:
    def __init__(self):self.stdin=io.StringIO();self.waited=False
    def wait(self,timeout=None):self.waited=True


class FakeGuard:
    state={'enabled':True,'phase':'watching'}
    events=[]
    switch_first=False
    def __init__(self,d):self.state=dict(type(self).state)
    def recover(self):return self.state
    def ingest(self,raw):
        type(self).events.append(raw)
        if self.switch_first and len(self.events)==1:
            self.state['phase']='rechecking';return {'action':'repeat_ippure_test','last_observed_at':raw['observed_at']}
        return {'action':'observation_unknown','last_observed_at':raw['observed_at']}


class NativeTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory();self.addCleanup(self.tmp.cleanup);self.directory=Path(self.tmp.name)
        (self.directory/'config.json').write_text('{}')
        FakeGuard.state={'enabled':True,'phase':'watching'};FakeGuard.events=[];FakeGuard.switch_first=False
    def test_latched_disabled_or_rechecking_never_collect(self):
        for state in [{'enabled':False,'phase':'watching'},{'enabled':True,'phase':'suspend_required'},{'enabled':True,'phase':'rechecking'}]:
            self.assertFalse(service.allowed(state))
        FakeGuard.state={'enabled':True,'phase':'suspend_required'}
        with patch.object(service,'Guard',FakeGuard),patch.object(service,'capture',side_effect=AssertionError('must not launch browser')):
            self.assertFalse(service.cycle(self.directory,{})['ok'])
    def test_real_capture_time_is_not_restamped(self):
        raw={'observed_at':time.time(),'rows':[]};child=Child()
        with patch.object(service,'Guard',FakeGuard),patch.object(service,'capture',return_value=(child,raw)):
            result=service.cycle(self.directory,{})
        self.assertTrue(result['ok']);self.assertEqual(FakeGuard.events,[raw]);self.assertTrue(child.waited)
        self.assertEqual(json.loads((self.directory/'native-live.json').read_text())['observed_at'],raw['observed_at'])
    def test_switch_requires_immediate_second_real_capture(self):
        FakeGuard.switch_first=True
        class Guard(FakeGuard):
            def ingest(self,raw):
                result=super().ingest(raw)
                if len(self.events)>1:self.state['phase']='watching'
                return result
        first,second={'observed_at':1},{'observed_at':2};one,two=Child(),Child()
        with patch.object(service,'Guard',Guard),patch.object(service,'capture',side_effect=[(one,first),(two,second)]) as capture:
            result=service.cycle(self.directory,{})
        self.assertEqual(capture.call_count,2);self.assertEqual(FakeGuard.events,[first,second]);self.assertTrue(result['ok'])
    def test_unaccepted_observation_not_ready(self):
        class Guard(FakeGuard):
            def ingest(self,raw):return {'action':'detector_channel_unverified'}
        with patch.object(service,'Guard',Guard),patch.object(service,'capture',return_value=(Child(),{'observed_at':1})):
            self.assertFalse(service.cycle(self.directory,{})['ok'])
    def test_new_scope_is_passed_to_pause_executor(self):
        scope={'scope_id':'fixture-scope','profile':'fixture','proxy':'http://127.0.0.1:29181'}
        adapter=Adapter({'profile':'fixture','browser_scope':scope})
        with patch('ippure_guard.browser_pause_latch.pause',return_value={'phase':'paused'}) as pause:
            adapter.pause(self.directory/'pause.json')
        self.assertEqual(pause.call_args.kwargs['scope'],scope)

    def exercise_loop(self,requested):
        (self.directory/'native-config.json').write_text(json.dumps({'interval_seconds':300}))
        clock=[0];sleeps=[0]
        def sleep(seconds):
            sleeps[0]+=1
            if sleeps[0]>1:raise RuntimeError('test_stop')
            clock[0]+=1 if requested else 301
            if requested:(self.directory/'native-request.json').write_text(json.dumps({'id':'new-launch-request'}))
        with patch.object(service,'cycle',return_value={'ok':True}) as cycle,patch.object(service.time,'time',side_effect=lambda:clock[0]),patch.object(service.time,'sleep',side_effect=sleep):
            with self.assertRaisesRegex(RuntimeError,'test_stop'):service.run(self.directory)
        self.assertEqual(cycle.call_count,2)
        return json.loads((self.directory/'native-status.json').read_text())

    def test_timer_runs_without_any_agent_request(self):
        status=self.exercise_loop(False);self.assertTrue(status['ok']);self.assertIsNone(status['request_id'])

    def test_launch_request_refreshes_before_interval_elapsed(self):
        status=self.exercise_loop(True);self.assertEqual(status['request_id'],'new-launch-request')

    def test_v2_uses_validated_portable_guard(self):
        (self.directory/'config.json').write_text('{"schema_version":2}')
        with patch('portable_guard.PortableGuard') as portable:
            self.assertIs(service.make_guard(self.directory),portable.return_value)
            portable.assert_called_once_with(self.directory)

    def test_retest_collection_failure_latches_after_switch(self):
        calls=[]
        class Guard:
            state={'enabled':True,'phase':'watching'}
            def __init__(self,d):pass
            def recover(self):return self.state
            def ingest(self,raw):self.state['phase']='rechecking';return {'action':'repeat_ippure_test'}
            def halt(self,reason):calls.append(reason);self.state['phase']='suspend_required';return {'phase':'suspend_required'}
        with patch.object(service,'Guard',Guard),patch.object(service,'capture',side_effect=[(Child(),{'observed_at':1}),RuntimeError('collection_failed')]):
            result=service.cycle(self.directory,{})
        self.assertFalse(result['ok']);self.assertEqual(calls,['native_retest_collection_failed'])


if __name__=='__main__':unittest.main()
