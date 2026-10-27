"""Explicit prepare/install/uninstall for private v2 guard bundles.

Init creates a disabled draft only. Prepare changes no client files. Install and
uninstall require recorded authorization, hash checks and a local reload adapter.
No browser or Claude process is launched. Profile data is never deleted.
"""
import argparse
import copy
import hashlib
import json
from pathlib import Path
import shutil
import socket
import subprocess
import uuid
from change_bundle import private_directory, read_bytes, executable_digest
from guard_config import validate
from guard_store import lock, save, write_bytes
from portable_guard import PortableAdapter


def sha(data):
    return hashlib.sha256(data).hexdigest()


def initialize(directory):
    directory = private_directory(directory)
    directory.mkdir(parents=True, exist_ok=False)
    config = json.loads((Path(__file__).resolve().parents[1] / 'assets/guard.example.json').read_text(encoding='utf-8'))
    profile = directory / 'browser-profile'; profile.mkdir()
    scope = str(uuid.uuid4())
    save(profile / '.proxy-env-doctor-scope.json', {'scope_id': scope})
    # Empty, independently created profile only; never import an existing profile.
    (profile / 'Default').mkdir()
    save(profile / 'Default/Preferences', {'webrtc': {'ip_handling_policy': 'disable_non_proxied_udp'}})
    config['browser'].update(profile=str(profile), scope_id=scope)
    runtime = shutil.which('node')
    config['node_runtime'] = str(Path(runtime).resolve()) if runtime else None
    save(directory / 'config.json', config)
    save(directory / 'state.json', {'phase':'watching', 'enabled':False, 'switch_count':0})
    return {'initialized': True, 'status':'draft', 'enabled':False, 'browser_launched':False}


def fragments(config):
    r = config['routing']
    return {'proxy-groups': [
        {'name':r['fallback'], 'type':'fallback', 'proxies':r['nodes'], 'url':'https://www.gstatic.com/generate_204', 'interval':300, 'lazy':False},
        {'name':r['group'], 'type':'select', 'proxies':[r['fallback'], *r['nodes'], 'REJECT']},
        {'name':r['probe_group'], 'type':'select', 'proxies':r['nodes']}],
        'listeners': [
        {'name':r['inbound'], 'type':'http', 'listen':'127.0.0.1', 'port':r['port'], 'proxy':r['group']},
        {'name':r['probe_inbound'], 'type':'http', 'listen':'127.0.0.1', 'port':r['probe_port'], 'proxy':r['probe_group']}]}


def candidate(source, config):
    out = copy.deepcopy(source); r = config['routing']; pieces = fragments(config)
    if out.get('mode') != 'global': raise ValueError('global_mode_required_no_implicit_mode_change')
    proxies = {p['name']:p for p in out.get('proxies', [])}
    for name in r['nodes']:
        p = proxies.get(name)
        if not p or p.get('type') in ('direct', 'reject') or p.get('dialer-proxy'):
            raise ValueError('explicit_physical_nodes_required_no_hidden_chains')
    used_names = set(proxies) | {g['name'] for g in out.get('proxy-groups', [])}
    if used_names & {g['name'] for g in pieces['proxy-groups']}: raise ValueError('group_name_collision')
    occupied = {out.get(k) for k in ('port','socks-port','mixed-port','redir-port','tproxy-port')}
    occupied |= {l.get('port') for l in out.get('listeners', [])}
    if occupied & {r['port'], r['probe_port']}: raise ValueError('listener_port_collision')
    if {l.get('name') for l in out.get('listeners', [])} & {r['inbound'],r['probe_inbound']}: raise ValueError('listener_name_collision')
    out.setdefault('proxy-groups', []).extend(pieces['proxy-groups'])
    out.setdefault('listeners', []).extend(pieces['listeners'])
    return out


def wrapper(original, config):
    marker = 'proxyEnvGuard_' + sha(json.dumps(config['routing'], sort_keys=True).encode())[:16]
    if marker in original: raise ValueError('wrapper_already_present')
    pieces = json.dumps(fragments(config), ensure_ascii=False)
    # No paths, baseline or authentication values enter the subscription extension.
    return original + '\nvar ' + marker + '=main;\nmain=function(config,profileName){\n' + \
        'config='+marker+'(config,profileName);\nvar additions='+pieces+';\n' + \
        'var names=new Set((config.proxies||[]).map(function(p){return p.name;}));\n' + \
        'var groupNames=new Set((config["proxy-groups"]||[]).map(function(g){return g.name;}));\n' + \
        'additions["proxy-groups"].forEach(function(g){if(groupNames.has(g.name)||names.has(g.name))throw new Error("Guard group collision");g.proxies=g.proxies.filter(function(n){return names.has(n)||n==="REJECT"||n===additions["proxy-groups"][0].name;});if(!g.proxies.length)g.proxies=["REJECT"];});\n' + \
        'var used=new Set((config.listeners||[]).map(function(l){return l.port;}));["port","socks-port","mixed-port","redir-port","tproxy-port"].forEach(function(k){used.add(config[k]);});\n' + \
        'additions.listeners.forEach(function(l){if(used.has(l.port)||(config.listeners||[]).some(function(x){return x.name===l.name;}))throw new Error("Guard listener collision");});\n' + \
        'config["proxy-groups"]=(config["proxy-groups"]||[]).concat(additions["proxy-groups"]);config.listeners=(config.listeners||[]).concat(additions.listeners);return config;\n};\n'


def prepare(directory, source, extension, core, working_directory):
    import yaml
    directory = private_directory(directory); config = validate(json.loads((directory/'config.json').read_text(encoding='utf-8')), check_files=True)
    if (directory/'deployment.json').exists(): raise ValueError('deployment_bundle_already_exists')
    source, extension, core, working_directory = [Path(p).resolve(strict=True) for p in (source,extension,core,working_directory)]
    if source == extension or not source.is_relative_to(working_directory) or not extension.is_relative_to(working_directory): raise ValueError('files_outside_declared_client_root')
    original, oldscript = read_bytes(source), read_bytes(extension)
    parsed = yaml.safe_load(original)
    rendered = yaml.safe_dump(candidate(parsed,config), allow_unicode=True, sort_keys=False).encode('utf-8')
    script = wrapper(oldscript.decode('utf-8-sig'),config).encode('utf-8')
    write_bytes(directory/'original.yaml',original); write_bytes(directory/'original.js',oldscript)
    write_bytes(directory/'candidate.yaml',rendered); write_bytes(directory/'candidate.js',script)
    subprocess.run([str(core),'-t','-d',str(working_directory),'-f',str(directory/'candidate.yaml')],capture_output=True,timeout=30,check=True)
    subprocess.run([config['node_runtime'],'--check',str(directory/'candidate.js')],capture_output=True,timeout=15,check=True)
    manifest={'phase':'prepared','source':str(source),'extension':str(extension),'core':str(core),'core_hash':executable_digest(core),
              'working_directory':str(working_directory),'config_hash':sha(read_bytes(directory/'config.json')),
              'original_yaml':sha(original),'original_js':sha(oldscript),'candidate_yaml':sha(rendered),'candidate_js':sha(script)}
    save(directory/'deployment.json',manifest)
    return {'prepared':True,'core_validated':True,'client_changed':False}


def bundle(directory):
    config=validate(json.loads((directory/'config.json').read_text(encoding='utf-8')),check_files=True)
    m=json.loads((directory/'deployment.json').read_text(encoding='utf-8'))
    if sha(read_bytes(directory/'config.json'))!=m['config_hash'] or executable_digest(Path(m['core']))!=m['core_hash']: raise ValueError('inputs_changed')
    for prefix in ('original','candidate'):
        for suffix in ('yaml','js'):
            if sha(read_bytes(directory/f'{prefix}.{suffix}'))!=m[f'{prefix}_{suffix}']: raise ValueError('bundle_changed')
    return config,m


def install(directory, adapter=None):
    config,m=bundle(directory); adapter=adapter or PortableAdapter(config,directory)
    if m['phase']!='prepared': raise ValueError('deployment_not_replayable')
    for target,suffix in ((m['source'],'yaml'),(m['extension'],'js')):
        if sha(read_bytes(Path(target)))!=m['original_'+suffix]: raise ValueError('client_changed')
    for port in (config['routing']['port'],config['routing']['probe_port']):
        with socket.socket() as probe: probe.bind(('127.0.0.1',port))
    snapshot=adapter.route('snapshot')
    if snapshot['mode']!='global': raise ValueError('runtime_mode_changed')
    save(directory/'selectors.json',snapshot)
    m['phase']='install_pending';save(directory/'deployment.json',m)
    try:
        write_bytes(Path(m['extension']),read_bytes(directory/'candidate.js'))
        write_bytes(Path(m['source']),read_bytes(directory/'candidate.yaml'))
        adapter.route('reload',file='candidate.yaml');adapter.route('restore-selectors')
        if not adapter.route('inspect').get('verified'): raise ValueError('runtime_verification_failed')
        if adapter.route('snapshot')['selectors'].get('GLOBAL') != snapshot['selectors'].get('GLOBAL'): raise ValueError('global_selection_changed')
        m['phase']='installed';save(directory/'deployment.json',m)
    except Exception:
        # Only undo our exact writes; never erase a later operator edit.
        for target,suffix in ((m['source'],'yaml'),(m['extension'],'js')):
            current=sha(read_bytes(Path(target)))
            if current not in (m['original_'+suffix],m['candidate_'+suffix]): raise RuntimeError('operator_edit_requires_manual_recovery')
            write_bytes(Path(target),read_bytes(directory/f'original.{suffix}'))
        adapter.route('reload',file='original.yaml');adapter.route('restore-selectors')
        m['phase']='rolled_back';save(directory/'deployment.json',m)
        raise
    return {'installed':True,'enabled':False,'global_selection_preserved':True}


def uninstall(directory, adapter=None):
    config,m=bundle(directory);adapter=adapter or PortableAdapter(config,directory)
    state=json.loads((directory/'state.json').read_text(encoding='utf-8'))
    if state.get('enabled'): raise ValueError('disable_guard_first_and_stop_scheduler')
    if (directory/'pause.json').exists() and json.loads((directory/'pause.json').read_text())['phase']!='resumed': raise ValueError('explicit_resume_required_before_uninstall')
    if m['phase']=='uninstalled':return {'uninstalled':True,'already_uninstalled':True}
    if m['phase'] not in ('installed','install_pending','uninstall_pending'):raise ValueError('unexpected_deployment_phase')
    for target,suffix in ((m['source'],'yaml'),(m['extension'],'js')):
        current=sha(read_bytes(Path(target)))
        if current not in (m['candidate_'+suffix],m['original_'+suffix]):raise ValueError('operator_edit_preserved')
    # Preserve operator selector changes made after installation, including GLOBAL.
    snap=adapter.route('snapshot'); originals=__import__('yaml').safe_load(read_bytes(directory/'original.yaml'))
    original_names={'GLOBAL'}|{g['name'] for g in originals.get('proxy-groups',[])}
    original_choices=original_names|{p['name'] for p in originals.get('proxies',[])}|{'DIRECT','REJECT'}
    if snap['mode']!=originals.get('mode') or snap['selectors'].get('GLOBAL') not in original_choices:
        raise ValueError('operator_runtime_choice_requires_review')
    snap['selectors']={k:v for k,v in snap['selectors'].items() if k in original_names}
    save(directory/'selectors.json',snap)
    m['phase']='uninstall_pending';save(directory/'deployment.json',m)
    write_bytes(Path(m['source']),read_bytes(directory/'original.yaml'))
    write_bytes(Path(m['extension']),read_bytes(directory/'original.js'))
    adapter.route('reload',file='original.yaml');adapter.route('restore-selectors')
    after=adapter.route('snapshot')
    if after['mode']!=snap['mode'] or after['selectors'].get('GLOBAL')!=snap['selectors'].get('GLOBAL'):raise RuntimeError('restore_runtime_mismatch')
    m['phase']='uninstalled';save(directory/'deployment.json',m)
    return {'uninstalled':True,'profile_and_evidence_preserved':True}


def discover(source, output):
    import yaml
    cfg=yaml.safe_load(read_bytes(source))
    # Explicit file only. Private output includes names, never node credentials.
    result={'source':'configuration_file_not_runtime','mode':cfg.get('mode'),
      'controller_candidates':{k:cfg.get(k) for k in ('external-controller','external-controller-pipe','external-controller-unix') if cfg.get(k)},
      'occupied_ports':[cfg[k] for k in ('mixed-port','port','socks-port','redir-port','tproxy-port') if cfg.get(k)],
      'listeners':[{k:l.get(k) for k in ('name','listen','port')} for l in cfg.get('listeners',[])],
      'physical_candidates':[p['name'] for p in cfg.get('proxies',[]) if p.get('type') not in ('direct','reject') and not p.get('dialer-proxy')],
      'qualification':'Names do not establish country, reachability or distinct exits. Verify local control endpoint independently.'}
    if output.exists():raise ValueError('new_private_output_required')
    private_directory(output.parent);save(output,result)
    return {'discovered':True,'network_accessed':False,'credentials_exported':False}


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('command',choices=['init','discover','prepare','install','uninstall'])
    parser.add_argument('--directory',required=True,type=Path)
    parser.add_argument('--source',type=Path);parser.add_argument('--extension',type=Path)
    parser.add_argument('--core',type=Path);parser.add_argument('--working-directory',type=Path)
    args=parser.parse_args();directory=private_directory(args.directory)
    if args.command=='init':result=initialize(directory)
    else:
        with lock(directory/'guard.lock'):
            if args.command=='discover':result=discover(args.source,directory/'discovery.json')
            elif args.command=='prepare':result=prepare(directory,args.source,args.extension,args.core,args.working_directory)
            else:result=globals()[args.command](directory)
    print(json.dumps(result))


if __name__=='__main__':
    try:main()
    except Exception:
        print(json.dumps({'error':'guard_lifecycle_failed','instruction':'Inspect private bundle phase; preserve operator changes and do not retry mutations blindly.'}))
        raise SystemExit(1)
