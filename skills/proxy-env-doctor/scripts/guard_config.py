"""Schema v2 for portable guard. Validation never changes host networking."""
import ipaddress
import json
from pathlib import Path
import re
from urllib.parse import urlsplit
from leak_policy import BASELINE_URL


def loopback(value):
    try:
        url = urlsplit(value)
        return (url.scheme == 'http' and url.hostname in ('127.0.0.1', '::1')
                and url.port is not None and 0 < url.port < 65536 and not url.username
                and not url.password and url.path in ('', '/') and not url.query and not url.fragment)
    except (ValueError, TypeError):
        return False


def validate(config, *, ready=True, check_files=False):
    if config.get('schema_version') != 2 or config.get('status') not in ('draft', 'ready'):
        raise ValueError('invalid_schema')
    permissions = ('local_read', 'client_modify', 'reload', 'public_probe', 'browser_pause')
    if any(type(config.get('authorization', {}).get(k)) is not bool for k in permissions):
        raise ValueError('invalid_authorization_record')
    if not ready:
        return config
    if config['status'] != 'ready' or not all(config['authorization'][k] for k in permissions):
        raise ValueError('record_existing_user_authorization_first')
    if not isinstance(config.get('region'), str) or not re.fullmatch('[A-Z]{2}', config['region']):
        raise ValueError('region_required')
    if not config.get('baseline_source') or not isinstance(config.get('broadband_ips'), list) or not config['broadband_ips']:
        raise ValueError('baseline_required')
    for value in config['broadband_ips']:
        ipaddress.ip_address(value)
    if config.get('detector_url') != BASELINE_URL or type(config.get('interval_seconds')) is not int or not 60 <= config['interval_seconds'] <= 3600:
        raise ValueError('invalid_detector')
    b, r, c = config['browser'], config['routing'], config['controller']
    if not b.get('profile') or not Path(b['profile']).is_absolute() or not b.get('scope_id') or not b.get('extension_instance'):
        raise ValueError('registered_browser_required')
    names = [r.get(k) for k in ('group', 'fallback', 'probe_group', 'inbound', 'probe_inbound')]
    if not all(isinstance(n, str) and 0 < len(n) <= 128 and not re.search(r'[\x00-\x1f]', n) for n in names) or len(set(names)) != len(names):
        raise ValueError('distinct_routing_names_required')
    nodes = r.get('nodes')
    reserved = {'GLOBAL', 'DIRECT', 'REJECT', 'REJECT-DROP'}
    if (not isinstance(nodes, list) or len(nodes) < 2 or len(nodes) > 16
            or not all(isinstance(n, str) and n and len(n) <= 256 and not re.search(r'[\x00-\x1f]', n) for n in nodes)
            or len(set(nodes)) != len(nodes) or (set(nodes) | set(names)) & reserved or set(nodes) & set(names)):
        raise ValueError('physical_node_allowlist_required')
    if r.get('mode') != 'global' or any(type(r.get(k)) is not int or not 1024 <= r[k] <= 65535 for k in ('port', 'probe_port')) or r['port'] == r['probe_port']:
        raise ValueError('distinct_unprivileged_ports_required')
    if not loopback(b.get('proxy')) or urlsplit(b['proxy']).hostname != '127.0.0.1' or urlsplit(b['proxy']).port != r['port']:
        raise ValueError('browser_proxy_mismatch')
    if bool(c.get('controller')) == bool(c.get('socket')):
        raise ValueError('one_controller_transport_required')
    if c.get('controller') and not loopback(c['controller']):
        raise ValueError('local_controller_required')
    if c.get('socket') and not (c['socket'].startswith('\\\\.\\pipe\\') or c['socket'].startswith('/')):
        raise ValueError('local_socket_required')
    if c.get('token_file') and not Path(c['token_file']).is_absolute():
        raise ValueError('absolute_token_file_required')
    if not config.get('node_runtime') or not Path(config['node_runtime']).is_absolute():
        raise ValueError('discovered_node_runtime_required')
    if check_files:
        profile = Path(b['profile']).resolve(strict=True)
        marker = json.loads((profile / '.proxy-env-doctor-scope.json').read_text(encoding='utf-8'))
        if marker != {'scope_id': b['scope_id']}:
            raise ValueError('profile_marker_mismatch')
        if not Path(config['node_runtime']).is_file():
            raise ValueError('node_runtime_missing')
        if c.get('token_file') and not Path(c['token_file']).is_file():
            raise ValueError('controller_token_missing')
    return config
