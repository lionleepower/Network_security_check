import copy
import unittest
from verify_route import evaluate


class RouteTests(unittest.TestCase):
    def setUp(self):
        self.plan = {'schema_version': 1, 'mode': 'global', 'claude': {'allow_failover': False, 'listener': 'dedicated'}}
        self.runtime = {'schema_version': 1, 'source': 'local-api', 'mode': 'global', 'expected_group_id': 'group-1',
                        'groups': [{'id': 'group-1', 'type': 'Selector', 'members': ['node-2'], 'selected': 'node-2'}],
                        'connections': [{'chains': ['node-2', 'group-1'], 'lifetime': 'started_after_capture', 'expected_inbound': True}]}

    def check_status(self, result, name):
        return next(c['status'] for c in result['checks'] if c['check'] == name)

    def test_public_route_evidence_never_proves_logged_in_session_or_all_protocols(self):
        result = evaluate(self.plan, self.runtime)
        self.assertEqual(self.check_status(result, 'dedicated_path'), 'pass')
        self.assertEqual(self.check_status(result, 'existing_claude_session'), 'unknown')
        self.assertEqual(result['status'], 'unknown')

    def test_shared_global_or_direct_is_not_a_dedicated_path(self):
        for unsafe in ['DIRECT', 'GLOBAL']:
            with self.subTest(unsafe=unsafe):
                runtime = copy.deepcopy(self.runtime)
                runtime['connections'][0]['chains'].append(unsafe)
                self.assertEqual(self.check_status(evaluate(self.plan, runtime), 'dedicated_path'), 'fail')

    def test_nested_shared_fallback_fails_fixed_path_contract(self):
        self.runtime['groups'][0]['members'] = ['group-3']
        self.runtime['groups'].append({'id': 'group-3', 'type': 'Fallback', 'members': ['node-2', 'DIRECT']})
        self.assertEqual(self.check_status(evaluate(self.plan, self.runtime), 'runtime_group_contract'), 'fail')

    def test_empty_members_and_unobserved_connections_remain_unknown(self):
        self.runtime['groups'][0]['members'] = []
        self.plan['claude']['allow_failover'] = True
        self.runtime['connections'] = []
        result = evaluate(self.plan, self.runtime)
        self.assertEqual(self.check_status(result, 'runtime_group_contract'), 'unknown')
        self.assertEqual(self.check_status(result, 'dedicated_path'), 'unknown')

    def test_old_connections_missing_inbound_fixture_and_unstable_capture_do_not_pass(self):
        variants = []
        for key, value in [('lifetime', 'preexisting'), ('expected_inbound', None)]:
            r = copy.deepcopy(self.runtime)
            r['connections'][0][key] = value
            variants.append(r)
        r = copy.deepcopy(self.runtime)
        r['source'] = 'offline-fixture'
        variants.append(r)
        r = copy.deepcopy(self.runtime)
        r['state_changed_during_capture'] = True
        variants.append(r)
        for runtime in variants:
            self.assertEqual(self.check_status(evaluate(self.plan, runtime), 'dedicated_path'), 'unknown')

    def test_empty_fallback_assertion_does_not_prove_real_failure(self):
        result = evaluate(self.plan, self.runtime, scenarios={'failure_rejection': {'method': 'isolated-substitute', 'status': 'pass'}})
        self.assertEqual(self.check_status(result, 'failure_rejection_substitute'), 'pass')
        self.assertEqual(self.check_status(result, 'failure_rejection'), 'unknown')

    def test_ui_disk_core_mismatch_is_reported(self):
        result = evaluate(self.plan, self.runtime, {'mode': 'rule'}, 'global')
        self.assertEqual(self.check_status(result, 'ui_disk_runtime_agreement'), 'fail')


if __name__ == '__main__':
    unittest.main()
