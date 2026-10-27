"""Offline checks: redaction, dependency cycles, malformed input, and no mutation."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('inspect_clash_config.py')
spec = importlib.util.spec_from_file_location('summary', SCRIPT)
summary = importlib.util.module_from_spec(spec)
spec.loader.exec_module(summary)


class SummaryTests(unittest.TestCase):
    def test_rules_marker_is_a_valid_dns_route(self):
        result = summary.inspect_config({'dns': {'nameserver': ['https://resolver.invalid/dns-query#RULES&h3=false']}})
        self.assertEqual(result['dns']['upstreams']['nameserver'][0]['route_reference'], 'RULES')

    def test_listener_summary_exposes_routing_but_not_credentials(self):
        data = {'proxy-groups': [{'name': 'private-group', 'type': 'select', 'proxies': ['DIRECT']}],
                'listeners': [{'name': 'private-listener', 'type': 'http', 'listen': '127.0.0.1', 'port': 18080,
                               'proxy': 'private-group', 'users': [{'username': 'PRIVATE', 'password': 'SECRET'}]},
                              {'name': 'other', 'type': 'http', 'listen': '0.0.0.0', 'port': 18081, 'proxy': 'DIRECT'}]}
        result = summary.inspect_config(data)
        self.assertTrue(result['listeners'][0]['loopback'])
        self.assertEqual(result['listeners'][0]['proxy_reference'], 'group-1')
        self.assertFalse(result['listeners'][1]['loopback'])
        self.assertEqual(result['listeners'][1]['proxy_reference'], 'DIRECT')
        for secret in ['private-group', 'private-listener', 'PRIVATE', 'SECRET']:
            self.assertNotIn(secret, json.dumps(result))

    def test_dns_options_and_interfaces_are_not_reported_as_broken_groups(self):
        config = {'dns': {'nameserver': ['https://resolver.invalid/dns-query#h3=true', 'https://resolver.invalid/dns-query#private-interface&h3=true']}}
        entries = summary.inspect_config(config)['dns']['upstreams']['nameserver']
        self.assertEqual(entries[0]['route_reference'], 'UNSPECIFIED')
        self.assertEqual(entries[0]['fragment_option_count'], 1)
        self.assertEqual(entries[1]['route_reference'], 'UNRESOLVED_ROUTE_OR_INTERFACE')
        self.assertNotIn('private-interface', json.dumps(entries))

    def test_secrets_redacted_and_cycle_detected(self):
        secret = 'SAMPLE-CREDENTIAL-MUST-NOT-APPEAR'
        config = {
            'mode': 'rule', 'secret': secret,
            'proxies': [{'name': secret, 'type': 'ss', 'password': secret, 'server': secret, 'dialer-proxy': 'auto'}],
            'proxy-groups': [{'name': 'auto', 'type': 'fallback', 'proxies': [secret, 'DIRECT', 'missing']}],
            'dns': {'nameserver': ['https://user:' + secret + '@resolver.invalid/private/' + secret + '#auto']},
            'rules': ['DOMAIN,' + secret + ',auto']}
        output = summary.inspect_config(config)
        encoded = json.dumps(output)
        self.assertNotIn(secret, encoded)
        self.assertNotIn('resolver.invalid', encoded)
        self.assertTrue(output['cycle_detected'])
        self.assertEqual(output['groups'][0]['ordered_references'], ['proxy-1', 'DIRECT', 'UNRESOLVED'])
        self.assertEqual(output['dns']['upstreams']['nameserver'][0]['route_reference'], 'group-1')

    def test_cli_is_read_only(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'config.yaml'
            contents = b'mode: rule\nproxies: []\nproxy-groups: []\ndns:\n  nameserver:\n  - https://1.1.1.1/dns-query#DIRECT\n'
            path.write_bytes(contents)
            result = subprocess.run([sys.executable, '-X', 'utf8', str(SCRIPT), '--config', str(path)], capture_output=True, text=True, encoding='utf-8')
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(json.loads(result.stdout)['scope'], 'static_file_only')
            self.assertEqual(path.read_bytes(), contents)
            self.assertEqual(sorted(p.name for p in Path(directory).iterdir()), ['config.yaml'])

    def test_parse_failure_does_not_echo_private_data(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'broken.yaml'
            path.write_text('secret: [SAMPLE-PRIVATE-VALUE\n', encoding='utf-8')
            result = subprocess.run([sys.executable, '-X', 'utf8', str(SCRIPT), '--config', str(path)], capture_output=True, text=True, encoding='utf-8')
            self.assertEqual(result.returncode, 1)
            self.assertNotIn('SAMPLE-PRIVATE-VALUE', result.stdout + result.stderr)
            self.assertNotIn('Traceback', result.stderr)


if __name__ == '__main__':
    unittest.main()
