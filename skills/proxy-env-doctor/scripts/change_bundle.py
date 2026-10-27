"""File transaction primitives. No HTTP, app launching, reloads or account access."""
import hashlib
import json
import os
from pathlib import Path
import tempfile
import subprocess


MAX_BYTES = 8 * 1024 * 1024


def digest(data):
    return hashlib.sha256(data).hexdigest()


def executable_digest(path):
    if path.is_symlink() or not path.is_file() or path.stat().st_size > 256 * 1024 * 1024:
        raise ValueError('Unsupported core binary')
    result = hashlib.sha256()
    with path.open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            result.update(chunk)
    return result.hexdigest()


def read_bytes(path):
    if path.is_symlink() or path.stat().st_size > MAX_BYTES:
        raise ValueError('Unsupported file')
    return path.read_bytes()


def private_directory(path):
    path = path.resolve()
    if any((p / '.git').exists() for p in [path, *path.parents]):
        raise ValueError('Bundle must be outside Git checkouts')
    return path


def atomic_write(path, data):
    descriptor, temp = tempfile.mkstemp(prefix='.proxy-env-', dir=path.parent)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def load_manifest(directory):
    directory = private_directory(directory)
    manifest = json.loads(read_bytes(directory / 'manifest.json'))
    if manifest.get('schema_version') != 1 or not isinstance(manifest.get('files'), list) or not 1 <= len(manifest['files']) <= 16:
        raise ValueError('Invalid manifest')
    root = Path(manifest['target_root']).resolve(strict=True)
    seen = set()
    for index, entry in enumerate(manifest['files']):
        target = Path(entry['target'])
        if target.is_symlink() or not target.is_absolute() or target.resolve(strict=True) != target or not target.is_relative_to(root) or target == root:
            raise ValueError('Target outside declared root')
        if target in seen or entry.get('index') != index:
            raise ValueError('Duplicate or invalid target')
        seen.add(target)
        for name, key in [('candidate', 'candidate_hash'), ('original', 'original_hash')]:
            if digest(read_bytes(directory / f'{name}-{index}.bin')) != entry[key]:
                raise ValueError('Bundle checksum mismatch')
    return manifest


def prepare(plan_path, changes_path, destination, core, core_config, working_directory):
    plan_data = read_bytes(plan_path)
    plan = json.loads(plan_data)
    if plan.get('status') != 'ready' or plan.get('authorization', {}).get('client_modify') is not True:
        raise ValueError('Record client modification authorization first')
    if plan.get('claude', {}).get('session_policy') != 'do-not-touch-existing':
        raise ValueError('Unsafe session policy')
    spec = json.loads(read_bytes(changes_path))
    root = Path(spec['target_root']).resolve(strict=True)
    if str(root) not in [str(Path(p).resolve(strict=True)) for p in plan.get('allowed_client_roots', [])]:
        raise ValueError('Target root was not recorded in authorization')
    entries = spec['files']
    if not isinstance(entries, list) or not 1 <= len(entries) <= 16:
        raise ValueError('Invalid change set')
    # Validate every source before creating the bundle. Preparation never writes target files.
    prepared, seen = [], set()
    for index, entry in enumerate(entries):
        supplied = Path(entry['target'])
        if supplied.is_symlink():
            raise ValueError('Symlink target')
        target = supplied.resolve(strict=True)
        if not target.is_file() or not target.is_relative_to(root) or target == root or target in seen:
            raise ValueError('Invalid target')
        seen.add(target)
        candidate = read_bytes(Path(entry['candidate']))
        if target.suffix.lower() in {'.yaml', '.yml'}:
            import yaml
            if not isinstance(yaml.safe_load(candidate), dict):
                raise ValueError('YAML candidate must be a mapping')
        prepared.append((target, read_bytes(target), candidate))
    core = core.resolve(strict=True)
    core_config = core_config.resolve(strict=True)
    working_directory = working_directory.resolve(strict=True)
    config_data = read_bytes(core_config)
    import yaml
    if not isinstance(yaml.safe_load(config_data), dict):
        raise ValueError('Invalid core candidate')
    if not any(candidate == config_data and target.suffix.lower() in {'.yaml', '.yml'} for target, original, candidate in prepared):
        raise ValueError('Validated full core candidate must be in the change set')
    core_hash = executable_digest(core)
    subprocess.run([str(core), '-t', '-d', str(working_directory), '-f', str(core_config)],
                   check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=30)
    if digest(read_bytes(core_config)) != digest(config_data):
        raise ValueError('Core candidate changed during validation')
    destination = private_directory(destination)
    destination.mkdir(parents=True, exist_ok=False)
    manifest = {'schema_version': 1, 'state': 'prepared', 'target_root': str(root), 'plan_hash': digest(plan_data),
                'validation': {'core': str(core), 'core_hash': core_hash, 'config_hash': digest(config_data)},
                'files': [], 'limits': 'File-only bundle. Formal client settings and reload are separate required steps.'}
    for index, (target, original, candidate) in enumerate(prepared):
        (destination / f'original-{index}.bin').write_bytes(original)
        (destination / f'candidate-{index}.bin').write_bytes(candidate)
        manifest['files'].append({'index': index, 'target': str(target), 'original_hash': digest(original), 'candidate_hash': digest(candidate)})
    (destination / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    return {'prepared': True, 'files': len(prepared), 'targets_modified': False, 'core_validation': 'passed', 'runtime_applied': False}


def apply(directory, plan_path):
    manifest = load_manifest(directory)
    if manifest['state'] != 'prepared' or digest(read_bytes(plan_path)) != manifest['plan_hash']:
        raise ValueError('Plan changed or bundle already used')
    validation = manifest.get('validation', {})
    if executable_digest(Path(validation['core'])) != validation['core_hash'] or not any(e['candidate_hash'] == validation['config_hash'] for e in manifest['files']):
        raise ValueError('Core validation no longer matches the bundle')
    for entry in manifest['files']:
        if digest(read_bytes(Path(entry['target']))) != entry['original_hash']:
            raise ValueError('Target changed since preparation')
    written = []
    try:
        for entry in manifest['files']:
            target = Path(entry['target'])
            atomic_write(target, read_bytes(directory / f"candidate-{entry['index']}.bin"))
            written.append(entry)
        manifest['state'] = 'files-applied'
        atomic_write(directory / 'manifest.json', json.dumps(manifest, indent=2).encode())
    except Exception:
        for entry in reversed(written):
            atomic_write(Path(entry['target']), read_bytes(directory / f"original-{entry['index']}.bin"))
        raise
    return {'files_applied': True, 'runtime_applied': False, 'next': 'Use the authorized formal client settings/reload path, then collect and verify evidence.'}


def restore(directory):
    manifest = load_manifest(directory)
    if manifest['state'] != 'files-applied':
        raise ValueError('Bundle is not applied')
    for entry in manifest['files']:
        if digest(read_bytes(Path(entry['target']))) != entry['candidate_hash']:
            raise ValueError('Later changes detected; compare before restoring')
    restored = []
    try:
        for entry in manifest['files']:
            atomic_write(Path(entry['target']), read_bytes(directory / f"original-{entry['index']}.bin"))
            restored.append(entry)
        manifest['state'] = 'files-restored'
        atomic_write(directory / 'manifest.json', json.dumps(manifest, indent=2).encode())
    except Exception:
        for entry in reversed(restored):
            atomic_write(Path(entry['target']), read_bytes(directory / f"candidate-{entry['index']}.bin"))
        raise
    return {'files_restored': True, 'runtime_restored': False, 'next': 'Restore original client settings and selections using the authorized client interface, then verify.'}
