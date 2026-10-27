import unittest
from leak_policy import BASELINE_URL, evaluate


class LeakPolicyTests(unittest.TestCase):
    def check(self, state=None, observation=None, **changes):
        event = {'kind': 'ippure_result', 'url': BASELINE_URL, 'observed_at': 100,
                 'candidate_ips': ['198.51.100.1'], 'proxy_exit': '203.0.113.1', 'complete': True}
        event.update(observation or {})
        return evaluate(state or {'phase': 'watching'}, event, now=changes.get('now', 101),
                        broadband_ips=changes.get('baseline', ['198.51.100.1']), approved_nodes=['approved-sg'])

    def test_positive_leak_switches_once(self):
        state, action = self.check()
        self.assertEqual(action, 'switch_once_to_verified_sg')
        self.assertEqual(state['phase'], 'switch_required')
        self.assertEqual(self.check(state)[1], 'await_verified_switch')

    def test_timeout_or_empty_never_pass(self):
        for values in [[], None, 'invalid']:
            self.assertEqual(self.check(observation={'candidate_ips': values})[1], 'observation_unknown')

    def test_stale_unrelated_or_missing_baseline_never_switch(self):
        self.assertEqual(self.check(now=200)[1], 'observation_unknown')
        self.assertEqual(self.check(observation={'url': 'https://example.com/'})[1], 'ignore_unrelated_evidence')
        self.assertEqual(self.check(baseline=[])[1], 'baseline_unknown')

    def test_ordinary_proxy_candidate_does_not_trigger(self):
        self.assertEqual(self.check(observation={'candidate_ips': ['203.0.113.1']})[1], 'no_baseline_leak_observed')
        self.assertEqual(self.check(observation={'candidate_ips': ['203.0.113.2']})[1], 'observation_unknown')

    def test_rejected_switch_receipts_suspend(self):
        state, _ = self.check()
        receipt = {'kind': 'switch_receipt', 'success': True, 'node': 'approved-sg', 'country': 'SG', 'exit_ip': '203.0.113.2', 'observed_at': 100}
        for override in [{'exit_ip': '203.0.113.1'}, {'country': 'US'}, {'node': 'unapproved'}, {'success': False}, {'observed_at': 1}]:
            with self.subTest(override=override):
                self.assertEqual(self.check(state, {**receipt, **override})[1], 'suspend_affected_instance')

    def test_second_positive_leak_suspends_without_second_switch(self):
        state = {'phase': 'rechecking', 'new_exit': '203.0.113.2', 'switched_at': 99}
        result, action = self.check(state)
        self.assertEqual(action, 'suspend_affected_instance')
        self.assertEqual(self.check(result)[1], 'report_failure')

    def test_retest_must_be_fresh_complete_and_after_switch(self):
        state = {'phase': 'rechecking', 'new_exit': '203.0.113.2', 'switched_at': 99}
        self.assertEqual(self.check(state, {'observed_at': 99})[1], 'observation_unknown')
        self.assertEqual(self.check(state, {'candidate_ips': []})[1], 'observation_unknown')
        result, action = self.check(state, {'candidate_ips': ['203.0.113.2']})
        self.assertEqual(result['phase'], 'recovered')
        self.assertEqual(action, 'report_recovery_for_test_scope')


if __name__ == '__main__':
    unittest.main()
