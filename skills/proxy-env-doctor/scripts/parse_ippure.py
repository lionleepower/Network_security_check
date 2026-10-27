"""Normalize observed IPPure table cells; never drives a browser or changes routes."""
import ipaddress
import re
from leak_policy import BASELINE_URL

EXPECTED = {
    ('stun.chat.bilibili.com', 3478), ('stun.hitv.com', 3478),
    ('stun.miwifi.com', 3478), ('stun.l.google.com', 19302),
    ('stun.cloudflare.com', 3478), ('global.stun.twilio.com', 3478),
    ('stun.nextcloud.com', 3478), ('stun.voip.blackberry.com', 3478),
    ('stun.freeswitch.org', 3478),
}


def parse(url, rows, observed_at):
    """Only pass actual result cells, never the whole page or its My IP header.

    Source, time and instance identity must be verified by the browser caller;
    a supplied JSON object is not independently authenticated evidence.
    """
    output = {'kind': 'ippure_result', 'url': url, 'observed_at': observed_at,
              'candidate_ips': [], 'complete': False, 'no_candidate_rows': 0,
              'unknown_rows': 0, 'parser_status': 'unknown'}
    if url != BASELINE_URL or not isinstance(rows, list) or len(rows) != len(EXPECTED):
        return output
    seen, candidates = set(), set()
    for row in rows:
        if not isinstance(row, dict) or not isinstance(row.get('server'), str) or not isinstance(row.get('result'), str):
            return output
        if len(row['server']) > 512 or len(row['result']) > 2048:
            return output
        match = re.match(r'^stun:([a-zA-Z0-9.-]+):(\d{1,5})', row['server'])
        key = (match[1].lower(), int(match[2])) if match else None
        if key not in EXPECTED or key in seen:
            return output
        seen.add(key)
        text = row['result'].strip()
        found = set()
        for token in re.findall(r'(?<![\w.:])[0-9a-fA-F:.]*[.:][0-9a-fA-F:.]+(?![\w.:])', text):
            try:
                found.add(str(ipaddress.ip_address(token)))
            except ValueError:
                pass
        candidates.update(found)
        if not found:
            if text == '未检测到WebRTC IP泄露':
                output['no_candidate_rows'] += 1
            else:
                output['unknown_rows'] += 1
    output['candidate_ips'] = sorted(candidates)
    output['complete'] = seen == EXPECTED and output['unknown_rows'] == 0
    output['parser_status'] = 'recognized' if output['complete'] else 'unknown'
    return output
