"""Build a new allowlisted public copy and ZIP; never stage, commit or upload.

Heuristic privacy checks supplement human review, not a secret-detection guarantee.
The output must not already exist. Git history is not included in the archive.
"""
import argparse
import hashlib
import json
from pathlib import Path
import re
import zipfile

ROOT_FILES = {'.gitignore', 'README.md', 'AGENTS.md', 'requirements-dev.txt'}
TREES = ('docs', 'skills/proxy-env-doctor', '.github/workflows')
EXTENSIONS = {'.md', '.py', '.cjs', '.json', '.yaml', '.yml'}
SKIP = {'__pycache__', '.pytest_cache'}
PATTERNS = {
    'personal_windows_path': re.compile(r'[A-Za-z]:[/\\]+Users[/\\]+(?!Public\b|Default\b|<)[\w.-]+', re.I),
    'personal_unix_path': re.compile(r'(?<!:)/(?:home|Users)/[a-zA-Z0-9_.-]+/'),
    'private_key': re.compile(r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----'),
    'github_token': re.compile(r'\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,})'),
    'service_key': re.compile(r'\bsk-(?:ant-)?[A-Za-z0-9_-]{24,}'),
    'url_credentials': re.compile(r'''https?://[^\s/<>"']+:[^\s/<>"']+@'''),
}


def findings(text):
    return [{'kind': name, 'line': text[:m.start()].count('\n') + 1}
            for name, pattern in PATTERNS.items() for m in pattern.finditer(text)]


def public_files(root):
    root = Path(root).resolve(strict=True)
    files = [root / name for name in sorted(ROOT_FILES)]
    for tree in TREES:
        directory = root / tree
        if directory.is_symlink():
            raise ValueError('symlink_not_publishable')
        for file in sorted(directory.rglob('*')):
            relative = file.relative_to(root)
            if file.is_symlink():
                raise ValueError('symlink_not_publishable')
            if SKIP.intersection(relative.parts) or file.suffix in ('.pyc', '.pyo'):
                continue
            if file.is_file():
                if file.suffix not in EXTENSIONS:
                    raise ValueError('unexpected_public_file_type')
                files.append(file)
    result = []
    for file in files:
        if file.is_symlink() or not file.resolve(strict=True).is_relative_to(root):
            raise ValueError('public_path_escaped_root')
        data = file.read_bytes()
        if len(data) > 2 * 1024 * 1024:
            raise ValueError('unexpected_large_file')
        text = data.decode('utf-8-sig')
        result.append((file.relative_to(root).as_posix(), data, findings(text)))
    return result


def build(root, output):
    output = Path(output).resolve()
    if output.exists():
        raise ValueError('new_output_directory_required')
    entries = public_files(root)
    alerts = [{'file': name, **hit} for name, _, hits in entries for hit in hits]
    if alerts:
        return {'built': False, 'findings': alerts}
    output.mkdir(parents=True, exist_ok=False)
    source = output / 'source'; source.mkdir()
    hashes = {}
    for name, data, _ in entries:
        target = source / name; target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        hashes[name] = hashlib.sha256(data).hexdigest()
    manifest = {'format': 1, 'scope': 'explicit_public_files_only', 'files': hashes,
                'privacy_check': 'heuristic_patterns_passed_requires_review',
                'git_history_included': False, 'uploaded': False}
    (output / 'manifest.json').write_text(json.dumps(manifest, indent=2), encoding='utf-8')
    archive = output / 'network-security-check-rc.zip'
    with zipfile.ZipFile(archive, 'x', zipfile.ZIP_DEFLATED) as bundle:
        for name, data, _ in entries:
            bundle.writestr('network-security-check/' + name, data)
    digest = hashlib.sha256(archive.read_bytes()).hexdigest()
    (output / 'SHA256SUMS.txt').write_text(digest + '  ' + archive.name + '\n', encoding='ascii')
    return {'built': True, 'files': len(entries), 'archive_sha256': digest, 'uploaded': False}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--root', type=Path, default=Path(__file__).resolve().parents[3])
    parser.add_argument('--output', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = build(args.root, args.output)
        print(json.dumps(result))
        return 0 if result['built'] else 1
    except (OSError, ValueError):
        print(json.dumps({'built': False, 'error': 'release_validation_failed'}))
        return 1


if __name__ == '__main__':
    raise SystemExit(main())
