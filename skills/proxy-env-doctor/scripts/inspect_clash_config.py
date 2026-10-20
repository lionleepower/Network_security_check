#!/usr/bin/env python3
"""Read-only, allowlisted summary of a Clash/Mihomo YAML file; never print secrets."""
import argparse
import json
from pathlib import Path
import sys
from urllib.parse import urlsplit


def inspect_config(data):
    if not isinstance(data, dict):
        raise ValueError('Root must be a mapping')
    proxies = data.get('proxies') or []
    groups = data.get('proxy-groups') or []
    if not isinstance(proxies, list) or not isinstance(groups, list):
        raise ValueError('Unsupported proxies/groups structure')
    ids = {}
    duplicates = 0
    for prefix, items in [('proxy', proxies), ('group', groups)]:
        for index, item in enumerate(items, 1):
            if not isinstance(item, dict) or not isinstance(item.get('name'), str):
                raise ValueError('Malformed named entry')
            name = item['name']
            duplicates += int(name in ids)
            ids[name] = f'{prefix}-{index}'
    builtins = {'DIRECT', 'REJECT', 'REJECT-DROP', 'PASS', 'COMPATIBLE', 'GLOBAL'}

    def ref(value):
        if not isinstance(value, str):
            return 'INVALID'
        return ids.get(value, value if value in builtins else 'UNRESOLVED')

    def flag(mapping, key):
        value = mapping.get(key)
        return value if isinstance(value, bool) else None

    def count(value):
        return len(value) if isinstance(value, (list, dict)) else 0

    def endpoints(value):
        values = value if isinstance(value, list) else [value]
        result = []
        for entry in values:
            if not isinstance(entry, str):
                result.append({'transport': 'invalid'})
                continue
            base, _, fragment = entry.partition('#')
            transport = 'udp'
            if base == 'system':
                transport = 'system'
            elif '://' in base:
                scheme = urlsplit(base).scheme.lower()
                transport = {'https': 'doh', 'tls': 'dot', 'quic': 'doq', 'h3': 'doh3', 'tcp': 'tcp', 'udp': 'udp'}.get(scheme, 'other')
            parts = fragment.split('&') if fragment else []
            first = parts[0] if parts else ''
            has_route = bool(first) and '=' not in first and first not in {'h3', 'skip-cert-verify'}
            route = ref(first) if has_route else 'UNSPECIFIED'
            if route == 'UNRESOLVED':
                route = 'UNRESOLVED_ROUTE_OR_INTERFACE'
            result.append({'transport': transport, 'route_reference': route,
                           'fragment_option_count': len(parts) - int(has_route)})
        return result

    group_rows = []
    graph = {}
    for group in groups:
        ident = ref(group['name'])
        members = group.get('proxies') or []
        if not isinstance(members, list):
            raise ValueError('Malformed group membership')
        references = [ref(n) for n in members]
        kind = group.get('type')
        row = {'id': ident, 'type': kind if kind in {'select', 'fallback', 'url-test', 'load-balance', 'relay'} else 'other',
               'ordered_references': references, 'provider_count': count(group.get('use')),
               'imports_all': any(group.get(k) is True for k in ['include-all', 'include-all-proxies', 'include-all-providers']),
               'empty_fallback': ref(group['empty-fallback']) if 'empty-fallback' in group else 'UNSPECIFIED',
               'health_url_configured': bool(group.get('url'))}
        group_rows.append(row)
        graph[ident] = [r for r in references if r.startswith('group-')]
    for proxy in proxies:
        if 'dialer-proxy' in proxy:
            graph[ref(proxy['name'])] = [ref(proxy['dialer-proxy'])]
    # Include proxy links so group -> proxy -> dialer-group loops are detectable.
    for row in group_rows:
        graph[row['id']] = [r for r in row['ordered_references'] if r.startswith(('group-', 'proxy-'))]
    active, finished, cyclic = set(), set(), set()

    def visit(node):
        if node in active:
            cyclic.add(node)
            return
        if node in finished:
            return
        active.add(node)
        for target in graph.get(node, []):
            visit(target)
        active.remove(node)
        finished.add(node)

    for node in graph:
        visit(node)
    dns = data.get('dns') or {}
    tun = data.get('tun') or {}
    if not isinstance(dns, dict) or not isinstance(tun, dict):
        raise ValueError('Malformed DNS/TUN')
    hijack = tun.get('dns-hijack') or []
    if not isinstance(hijack, list):
        hijack = []
    mode = data.get('mode')
    stack = tun.get('stack')
    return {
        'scope': 'static_file_only', 'mode': mode if mode in {'rule', 'global', 'direct'} else 'unspecified-or-other',
        'ipv6': flag(data, 'ipv6'), 'proxy_count': len(proxies), 'duplicate_name_count': duplicates,
        'groups': group_rows, 'cycle_detected': bool(cyclic), 'cycle_entry_ids': sorted(cyclic),
        'rules_count': count(data.get('rules')), 'rule_provider_count': count(data.get('rule-providers')),
        'tun': {**{k: flag(tun, k) for k in ['enable', 'auto-route', 'auto-detect-interface', 'strict-route']},
                'stack': stack if stack in {'system', 'gvisor', 'mixed', 'mips'} else 'unspecified-or-other',
                'udp_any_53': 'any:53' in hijack or 'udp://any:53' in hijack,
                'tcp_any_53': 'tcp://any:53' in hijack,
                'route_exclusion_count': count(tun.get('route-exclude-address'))},
        'dns': {**{k: flag(dns, k) for k in ['enable', 'ipv6', 'respect-rules']},
                'upstreams': {k: endpoints(dns[k]) for k in ['nameserver', 'fallback', 'default-nameserver', 'proxy-server-nameserver', 'direct-nameserver'] if k in dns},
                'policy_counts': {k: count(dns.get(k)) for k in ['nameserver-policy', 'proxy-server-nameserver-policy']}},
        'control': {'tcp_configured': bool(data.get('external-controller')), 'pipe_configured': bool(data.get('external-controller-pipe'))},
        'limits': 'No live verification. DNS policy contents, interface routes, provider payloads, sub-rules and hostname resolution are not analyzed.'
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--config', required=True, type=Path)
    args = parser.parse_args()
    try:
        import yaml
    except ImportError:
        print('PyYAML is unavailable; use an existing safe parser. No dependency was installed.', file=sys.stderr)
        return 2
    try:
        if args.config.stat().st_size > 8 * 1024 * 1024:
            raise ValueError('Configuration exceeds summary size limit')
        data = yaml.safe_load(args.config.read_text(encoding='utf-8-sig'))
        result = inspect_config(data)
    except (OSError, ValueError, TypeError, RecursionError, yaml.YAMLError):
        print('Unable to summarize this configuration safely. No file contents or parser details were printed.', file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
