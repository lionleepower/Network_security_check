import json
from pathlib import Path
import tempfile
import time
import unittest
from guard_store import save
from ippure_guard import Guard
from parse_ippure import EXPECTED
from leak_policy import BASELINE_URL


class Fake:
    def __init__(self):
        self.calls = []
        self.crash = False

    def route(self, action, **data):
        self.calls.append(action)
        if action == 'switch':
            if self.crash:
                raise KeyboardInterrupt('simulated caller termination')
            return {'kind': 'switch_receipt', 'success': True, 'node': 'SG-B', 'country': 'SG', 'exit_ip': '203.0.113.2', 'observed_at': time.time()}
        return {'verified': True, 'blocked': True, 'enabled': True}

    def pause(self, journal):
        self.calls.append('pause'); return {'phase': 'paused', 'count': 2}

    def resume(self, journal):
        self.calls.append('resume'); return {'phase': 'resumed', 'count': 2}


class GuardTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        save(self.directory / 'config.json', {'broadband_ips': ['198.51.100.77'], 'approved_nodes': ['SG-B'], 'extension_instance': 'test'})
        self.adapter = Fake(); self.guard = Guard(self.directory, self.adapter); self.guard.enable()

    def observation(self, result='198.51.100.77'):
        return {'source': 'live-browser', 'extension_instance': 'test', 'observed_at': time.time(), 'url': BASELINE_URL,
                'proxy_exit': '203.0.113.1', 'rows': [{'server': f'stun:{host}:{port}', 'result': result} for host, port in EXPECTED]}

    def test_repeated_leak_pauses_once_switch_budget(self):
        self.assertEqual(self.guard.ingest(self.observation())['phase'], 'rechecking')
        self.assertEqual(self.guard.ingest(self.observation())['phase'], 'suspend_required')
        restarted = Guard(self.directory, self.adapter)
        restarted.ingest(self.observation())
        self.assertEqual(self.adapter.calls.count('switch'), 1)
        self.assertIn('pause', self.adapter.calls)

    def test_crash_before_switch_receipt_never_replays(self):
        self.adapter.crash = True
        with self.assertRaises(KeyboardInterrupt):
            self.guard.ingest(self.observation())
        restarted = Guard(self.directory, self.adapter)
        self.assertEqual(restarted.recover()['phase'], 'suspend_required')
        self.assertEqual(self.adapter.calls.count('switch'), 1)

    def test_empty_candidates_and_stale_do_not_switch(self):
        raw = self.observation('未检测到WebRTC IP泄露')
        self.assertEqual(self.guard.ingest(raw)['action'], 'observation_unknown')
        self.assertEqual(self.guard.ingest(raw)['action'], 'invalid_or_stale_observation')
        self.assertNotIn('switch', self.adapter.calls)

    def test_wrong_browser_rejected(self):
        raw = self.observation(); raw['extension_instance'] = 'other'
        self.assertEqual(self.guard.ingest(raw)['action'], 'invalid_or_stale_observation')
        self.assertNotIn('switch', self.adapter.calls)

    def test_manual_resume_does_not_rearm_or_unblock(self):
        self.guard.halt('synthetic_test')
        self.adapter.calls.clear()
        result = self.guard.manual_resume()
        self.assertFalse(result['enabled'])
        self.assertEqual(self.adapter.calls, ['resume'])
        self.guard.ingest(self.observation())
        self.assertEqual(self.adapter.calls, ['resume'])

    def test_block_failure_still_attempts_pause(self):
        original = self.adapter.route
        def failing(action, **data):
            if action == 'block': raise OSError('offline')
            return original(action, **data)
        self.adapter.route = failing
        result = self.guard.halt('test')
        self.assertFalse(result['entry_blocked'])
        self.assertIn('pause', self.adapter.calls)

    def test_suspended_journal_prevents_rearm(self):
        save(self.directory / 'pause.json', {'phase': 'paused'})
        with self.assertRaises(RuntimeError): self.guard.enable()


if __name__ == '__main__': unittest.main()
