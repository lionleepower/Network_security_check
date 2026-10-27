"""Pure decision logic for an IPPure incident; no browser, routing or process actions.

The caller must supply independently collected, fresh evidence from the designated
isolated browser. JSON input and unit tests alone do not establish a live detector.
"""
from ipaddress import ip_address


BASELINE_URL = 'https://ippure.com/Browser-WebRTC-Leak-Detect'


def address(value):
    try:
        return str(ip_address(value))
    except (ValueError, TypeError):
        return None


def evaluate(state, observation, *, now, broadband_ips, approved_nodes, expected_country='SG'):
    """Return the next state and requested action. Never executes the action.

    One incident permits one successful switch. A second positive leak requests
    suspension of the affected isolated instance, never a shared Claude process.
    Unknown results do not clear an incident or authorize another switch.
    """
    phase = state.get('phase', 'watching')
    if phase == 'suspend_required':
        return dict(state), 'report_failure'
    if observation.get('kind') == 'switch_receipt':
        if phase != 'switch_required':
            return dict(state), 'ignore_unexpected_receipt'
        old_ip, new_ip = address(state.get('previous_exit')), address(observation.get('exit_ip'))
        verified = observation.get('node') in approved_nodes and observation.get('country') == expected_country
        stamp = observation.get('observed_at')
        fresh = isinstance(stamp, (int, float)) and 0 <= now - stamp <= 90
        if observation.get('success') is not True or not verified or not fresh or not new_ip or not old_ip or new_ip == old_ip:
            return {**state, 'phase': 'suspend_required', 'reason': 'switch_not_verified'}, 'suspend_affected_instance'
        return {**state, 'phase': 'rechecking', 'new_exit': new_ip, 'switched_at': stamp}, 'repeat_ippure_test'
    if observation.get('kind') != 'ippure_result' or observation.get('url') != BASELINE_URL:
        return dict(state), 'ignore_unrelated_evidence'
    stamp = observation.get('observed_at')
    if not isinstance(stamp, (int, float)) or not 0 <= now - stamp <= 90:
        return dict(state), 'observation_unknown'
    if phase == 'switch_required':
        return dict(state), 'await_verified_switch'
    if phase == 'rechecking' and stamp <= state.get('switched_at', now):
        return dict(state), 'observation_unknown'
    baseline = {address(v) for v in broadband_ips} - {None}
    if not baseline:
        return dict(state), 'baseline_unknown'
    values = observation.get('candidate_ips')
    if not isinstance(values, list):
        return dict(state), 'observation_unknown'
    candidates = {address(v) for v in values} - {None}
    if baseline & candidates:
        if phase == 'rechecking':
            return {**state, 'phase': 'suspend_required', 'reason': 'leak_after_switch'}, 'suspend_affected_instance'
        old_ip = address(observation.get('proxy_exit'))
        if not old_ip or not approved_nodes:
            return {**state, 'phase': 'suspend_required', 'reason': 'no_verified_switch_path'}, 'suspend_affected_instance'
        action = 'switch_once_to_verified_sg' if expected_country == 'SG' else 'switch_once_to_verified_region'
        return {'phase': 'switch_required', 'previous_exit': old_ip, 'detected_at': stamp}, action
    # No candidates or incomplete/unknown rows cannot establish protection.
    if not candidates or observation.get('complete') is not True:
        return dict(state), 'observation_unknown'
    expected = address(state.get('new_exit') if phase == 'rechecking' else observation.get('proxy_exit'))
    if not expected or candidates != {expected}:
        return dict(state), 'observation_unknown'
    if phase == 'rechecking':
        return {**state, 'phase': 'recovered', 'reason': 'same_baseline_retest_passed'}, 'report_recovery_for_test_scope'
    return dict(state), 'no_baseline_leak_observed'
