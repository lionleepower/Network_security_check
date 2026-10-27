import unittest
from leak_policy import BASELINE_URL, evaluate
from parse_ippure import EXPECTED, parse


class IPPureParserTests(unittest.TestCase):
    def rows(self):
        return [{'server':f'stun:{host}:{port}GlobalLabel','result':'未检测到WebRTC IP泄露'} for host,port in sorted(EXPECTED)]

    def test_current_table_is_recognized_but_not_network_pass(self):
        result = parse(BASELINE_URL,self.rows(),100)
        self.assertTrue(result['complete'])
        self.assertEqual(result['no_candidate_rows'],9)
        self.assertEqual(result['candidate_ips'],[])
        self.assertEqual(evaluate({'phase':'watching'},result,now=101,broadband_ips=['198.51.100.77'],approved_nodes=['sg'])[1],'observation_unknown')

    def test_positive_ip_triggers_without_misreading_stun_port(self):
        rows=self.rows();rows[0]['result']='198.51.100.77'
        result=parse(BASELINE_URL,rows,100);result['proxy_exit']='203.0.113.2'
        self.assertEqual(result['candidate_ips'],['198.51.100.77'])
        self.assertEqual(evaluate({'phase':'watching'},result,now=101,broadband_ips=['198.51.100.77'],approved_nodes=['sg'])[1],'switch_once_to_verified_sg')

    def test_ipv6_candidate_normalized(self):
        rows=self.rows();rows[0]['result']='2001:db8::77'
        self.assertEqual(parse(BASELINE_URL,rows,100)['candidate_ips'],['2001:db8::77'])

    def test_changed_missing_duplicate_or_other_page_unknown(self):
        rows=self.rows()
        self.assertFalse(parse(BASELINE_URL,rows[:-1],100)['complete'])
        self.assertFalse(parse('https://example.com/',rows,100)['complete'])
        rows[-1]=rows[0]
        self.assertFalse(parse(BASELINE_URL,rows,100)['complete'])

    def test_pending_or_unrecognized_text_never_passes(self):
        rows=self.rows();rows[0]['result']='检测中'
        self.assertFalse(parse(BASELINE_URL,rows,100)['complete'])


if __name__ == '__main__':
    unittest.main()
