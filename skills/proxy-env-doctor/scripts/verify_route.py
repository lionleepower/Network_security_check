#!/usr/bin/env python3
"""Evaluate redacted evidence offline. Never contacts Claude or controls applications."""
import argparse
import json
from pathlib import Path


def evaluate(plan, runtime, disk=None, ui_mode=None, scenarios=None):
    if plan.get('schema_version') != 1 or runtime.get('schema_version') != 1:
        raise ValueError('Unsupported evidence schema')
    checks = []

    def add(name, status, reason, scope='configuration'):
        checks.append({'check': name, 'status': status, 'reason': reason, 'scope': scope})

    live = runtime.get('source') == 'local-api'
    changed = runtime.get('state_changed_during_capture') is True
    add('requested_mode', ('pass' if runtime.get('mode') == plan.get('mode') else 'fail') if live else 'unknown',
        'Compare the requested mode with the observed core mode; fixtures are not live evidence.')
    if disk is None or ui_mode is None:
        add('ui_disk_runtime_agreement', 'unknown', 'UI mode and static disk summary are both required.')
    else:
        consistent = ui_mode == disk.get('mode') == runtime.get('mode') == plan.get('mode')
        add('ui_disk_runtime_agreement', ('pass' if consistent else 'fail') if live else 'unknown',
            'Agreement is a point-in-time observation, not a restart persistence test.')
    group_id = runtime.get('expected_group_id')
    groups = {g['id']: g for g in runtime.get('groups', [])}
    expected = groups.get(group_id)
    forbidden, incomplete = set(), False
    active, done = set(), set()

    def visit(ref):
        nonlocal incomplete
        if ref in {'DIRECT', 'GLOBAL', 'UNRESOLVED'}:
            forbidden.add(ref)
            return
        if ref in active:
            forbidden.add('cycle')
            return
        if ref in done or ref in {'REJECT', 'REJECT-DROP'}:
            return
        if ref.startswith('node-'):
            return  # Runtime group graph cannot inspect node-level dialer-proxy settings.
        group = groups.get(ref)
        if group is None:
            incomplete = True
            return
        active.add(ref)
        if not plan.get('claude', {}).get('allow_failover', False):
            if group.get('type') != 'Selector' or len(group.get('members', [])) != 1:
                forbidden.add('not-single-path')
        if not group.get('members'):
            incomplete = True
        for member in group.get('members', []):
            visit(member)
        active.remove(ref)
        done.add(ref)

    if expected:
        visit(group_id)
    else:
        incomplete = True
    group_status = 'fail' if forbidden else ('unknown' if incomplete else 'pass')
    add('runtime_group_contract', group_status if live else 'unknown',
        'Runtime group membership check only; node-level upstreams and provider import policy need static review.')
    if changed:
        add('capture_stability', 'unknown', 'Core state changed during capture; capture again in a stable state.')
    rows = [c for c in runtime.get('connections', []) if c.get('lifetime') == 'started_after_capture']
    matches = [c for c in rows if group_id is not None and group_id in c.get('chains', [])]
    if not live or changed or not rows:
        add('dedicated_path', 'unknown', 'No stable live evidence of new targeted connections.', 'observed-network')
    elif any('DIRECT' in c.get('chains', []) for c in rows):
        add('dedicated_path', 'fail', 'A new targeted connection contains DIRECT.', 'observed-network')
    elif len(matches) != len(rows):
        add('dedicated_path', 'fail', 'A targeted connection does not contain the expected dedicated group.', 'observed-network')
    elif plan.get('mode') == 'global' and (not plan.get('claude', {}).get('listener') or not all(c.get('expected_inbound') is True for c in rows)):
        add('dedicated_path', 'unknown', 'Global mode requires observed use of the dedicated inbound.', 'observed-network')
    elif any('GLOBAL' in c.get('chains', []) for c in rows):
        add('dedicated_path', 'fail', 'The supposedly independent chain still includes GLOBAL.', 'observed-network')
    else:
        add('dedicated_path', 'pass', 'New test-target connections use the expected route; this is not account validation.', 'observed-network')
    for name in ['failure_rejection', 'independence_from_global', 'client_regeneration', 'restart_persistence']:
        item = (scenarios or {}).get(name)
        status = 'unknown'
        reason = 'No scenario evidence supplied.'
        if item:
            # Keep substitutions useful without upgrading them into real production failure evidence.
            if item.get('method') == 'isolated-substitute':
                reason = 'Substitute scenario supplied; real scenario remains unverified.'
                add(name + '_substitute', item.get('status') if item.get('status') in {'pass', 'fail'} else 'unknown',
                    'Operator-supplied isolated evidence, not a real-node or actual-session test.', 'isolated-test')
            elif item.get('method') == 'operator-observation' and item.get('status') in {'pass', 'fail'}:
                status = item['status']
                reason = 'Operator-supplied observation; inspect the referenced private evidence separately.'
            else:
                reason = 'Unrecognized scenario evidence.'
        add(name, status, reason, 'operator-evidence')
    add('existing_claude_session', 'unknown', 'Existing logged-in sessions are deliberately not opened or operated.', 'actual-session')
    add('all_protocols_no_leak', 'unknown', 'No broad DNS, IPv6, UDP or proxy-exit guarantee follows from route evidence.', 'system')
    overall = 'fail' if any(c['status'] == 'fail' for c in checks) else ('unknown' if any(c['status'] == 'unknown' for c in checks) else 'pass')
    return {'schema_version': 1, 'status': overall, 'checks': checks,
            'limits': 'Evaluation classifies supplied evidence; it does not authenticate operator assertions or authorize actions.'}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True, type=Path)
    parser.add_argument('--runtime', required=True, type=Path)
    parser.add_argument('--disk', type=Path)
    parser.add_argument('--ui-mode', choices=['global', 'rule', 'direct'])
    parser.add_argument('--scenarios', type=Path)
    args = parser.parse_args()
    try:
        def read(p):
            if p.stat().st_size > 16 * 1024 * 1024:
                raise ValueError('Input too large')
            return json.loads(p.read_text(encoding='utf-8-sig'))
        result = evaluate(read(args.plan), read(args.runtime), read(args.disk) if args.disk else None,
                          args.ui_mode, read(args.scenarios) if args.scenarios else None)
    except (OSError, ValueError, TypeError, KeyError, AttributeError):
        print('Unable to evaluate evidence safely; no input contents were printed.')
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return {'pass': 0, 'fail': 1, 'unknown': 2}[result['status']]


if __name__ == '__main__':
    raise SystemExit(main())
