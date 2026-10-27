"""Durable one-cycle guard. A supported browser collector supplies live cells.

Scheduled heartbeat invokes this CLI. No browser automation or Claude execution.
All state, baseline and adapter configuration must stay in a private directory.
"""
import argparse
import json
from pathlib import Path
import subprocess
import time
from guard_store import lock, save
from leak_policy import evaluate
from parse_ippure import parse
import browser_pause_latch


class Adapter:
    def __init__(self, config):
        self.config = config

    def route(self, action, **data):
        result = subprocess.run(self.config['adapter_command'] + [action], input=json.dumps(data),
                                capture_output=True, text=True, timeout=100, check=True)
        return json.loads(result.stdout)

    def pause(self, journal):
        return browser_pause_latch.pause(Path(self.config['profile']), journal, scope=self.config.get('browser_scope'))

    def resume(self, journal):
        return browser_pause_latch.resume(journal)


class Guard:
    def __init__(self, directory, adapter=None):
        self.directory = Path(directory)
        self.config = json.loads((self.directory / 'config.json').read_text(encoding='utf-8'))
        self.path = self.directory / 'state.json'
        self.journal = self.directory / 'pause.json'
        self.state = json.loads(self.path.read_text(encoding='utf-8')) if self.path.exists() else {'phase': 'watching', 'enabled': False, 'switch_count': 0}
        self.adapter = adapter or Adapter(self.config)

    def write(self):
        self.state['updated_at'] = time.time()
        save(self.path, self.state)

    def halt(self, reason):
        self.state.update(phase='suspend_required', reason=reason, action='pause_pending')
        self.write()
        # Network rejection is defense in depth. A failed API must not skip pause.
        try:
            self.state['entry_blocked'] = self.adapter.route('block').get('blocked') is True
        except Exception:
            self.state['entry_blocked'] = False
        try:
            self.state['pause_result'] = self.adapter.pause(self.journal)
            self.state['action'] = 'paused_manual_recovery_required'
        except Exception:
            self.state['action'] = 'pause_incomplete_review_required'
        self.write()
        return self.summary()

    def ingest(self, raw):
        if not self.state.get('enabled'):
            return self.summary()
        if self.state['phase'] == 'switch_required':
            return self.halt('interrupted_switch_no_retry')
        if self.state['phase'] == 'suspend_required':
            return self.halt(self.state.get('reason', 'latched_failure'))
        now = time.time()
        stamp = raw.get('observed_at', 0)
        if (raw.get('source') != self.config.get('evidence_mode', 'live-browser') or raw.get('extension_instance') != self.config['extension_instance']
                or not isinstance(stamp, (int, float)) or not 0 <= now - stamp <= 90
                or stamp <= self.state.get('last_observed_at', 0)):
            self.state['action'] = 'invalid_or_stale_observation'; self.write(); return self.summary()
        route = self.adapter.route('check')
        if not route.get('verified'):
            self.state['action'] = 'detector_channel_unverified'; self.write(); return self.summary()
        observation = parse(raw.get('url'), raw.get('rows'), stamp)
        observation['proxy_exit'] = raw.get('proxy_exit')
        previous = dict(self.state)
        state, action = evaluate(self.state, observation, now=now,
                                 broadband_ips=self.config['broadband_ips'], approved_nodes=self.config['approved_nodes'],
                                 expected_country=self.config.get('region', 'SG'))
        self.state = {**previous, **state, 'action': action, 'last_observed_at': stamp,
                      'no_candidate_rows': observation['no_candidate_rows'], 'candidate_count': len(observation['candidate_ips'])}
        self.write()
        if action == 'suspend_affected_instance':
            return self.halt(self.state['reason'])
        if action in ('switch_once_to_verified_sg', 'switch_once_to_verified_region'):
            if self.state.get('switch_count', 0):
                return self.halt('single_switch_budget_exhausted')
            # Intent is committed BEFORE the mutation. A crash cannot replay it.
            self.state['switch_count'] = 1; self.write()
            try:
                receipt = self.adapter.route('switch', previous_exit=self.state['previous_exit'])
            except Exception:
                return self.halt('switch_failed_or_interrupted')
            state, action = evaluate(self.state, receipt, now=time.time(),
                                     broadband_ips=self.config['broadband_ips'], approved_nodes=self.config['approved_nodes'],
                                     expected_country=self.config.get('region', 'SG'))
            self.state.update(state, action=action); self.write()
            if action == 'suspend_affected_instance':
                return self.halt(self.state['reason'])
        return self.summary()

    def recover(self):
        if self.state['phase'] == 'switch_required':
            return self.halt('interrupted_switch_no_retry')
        if self.state['phase'] == 'suspend_required':
            return self.halt(self.state.get('reason', 'latched_failure'))
        return self.summary()

    def manual_resume(self):
        self.state['enabled'] = False
        self.state['action'] = 'manual_resume_pending'; self.write()
        # Keep the HTTP entry rejected during and after resume, until explicit enable.
        result = self.adapter.resume(self.journal)
        self.state.update(phase='manual_recovery', action='resumed_guard_disabled', resume_result=result)
        self.write(); return self.summary()

    def enable(self):
        if self.journal.exists() and json.loads(self.journal.read_text(encoding='utf-8'))['phase'] != 'resumed':
            raise RuntimeError('resume_first')
        result = self.adapter.route('enable')
        if not result.get('enabled'):
            raise RuntimeError('route_enable_failed')
        self.state = {'phase': 'watching', 'enabled': True, 'switch_count': 0, 'action': 'awaiting_live_observation'}
        self.write(); return self.summary()

    def summary(self):
        keys = ('phase', 'enabled', 'action', 'reason', 'switch_count', 'last_observed_at', 'no_candidate_rows', 'candidate_count', 'entry_blocked', 'pause_result', 'resume_result')
        result = {k: self.state[k] for k in keys if k in self.state}
        result['collection_stale'] = time.time() - self.state.get('last_observed_at', 0) > self.config.get('interval_seconds', 300) + 120
        return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--directory', required=True, type=Path)
    parser.add_argument('command', choices=['ingest', 'status', 'recover', 'resume', 'enable', 'disable'])
    parser.add_argument('--input', type=Path)
    args = parser.parse_args()
    with lock(args.directory / 'guard.lock'):
        guard = Guard(args.directory)
        if args.command == 'ingest':
            result = guard.ingest(json.loads(args.input.read_text(encoding='utf-8')))
        elif args.command == 'disable':
            guard.state['enabled'] = False; guard.write(); result = guard.summary()
        else:
            result = getattr(guard, {'status': 'summary', 'resume': 'manual_resume'}.get(args.command, args.command))()
        print(json.dumps(result))


if __name__ == '__main__':
    try:
        main()
    except Exception:
        print(json.dumps({'error': 'guard_operation_failed', 'instruction': 'Inspect private state; do not auto-resume or repeat switch.'}))
        raise SystemExit(1)
