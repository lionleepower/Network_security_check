#!/usr/bin/env python3
"""Validate this skill's metadata, example intent and local Markdown references."""
import json
from pathlib import Path
import re
import sys


def main():
    try:
        import yaml
    except ImportError:
        print('PyYAML is required for full validation; nothing was installed.')
        return 2
    root = Path(__file__).resolve().parents[1]
    try:
        body = (root / 'SKILL.md').read_text(encoding='utf-8')
        match = re.match(r'^---\n(.*?)\n---\n', body, re.S)
        if not match:
            raise ValueError('Invalid frontmatter')
        metadata = yaml.safe_load(match[1])
        if metadata.get('name') != root.name or not re.fullmatch(r'[a-z0-9]+(?:-[a-z0-9]+)*', metadata['name']):
            raise ValueError('Invalid skill name')
        description = metadata.get('description')
        if not isinstance(description, str) or not 1 <= len(description) <= 1024:
            raise ValueError('Invalid description')
        interface = yaml.safe_load((root / 'agents/openai.yaml').read_text(encoding='utf-8'))['interface']
        if not 25 <= len(interface['short_description']) <= 64 or '$' + root.name not in interface['default_prompt']:
            raise ValueError('Invalid UI metadata')
        links = 0
        for file in root.rglob('*.md'):
            text = file.read_text(encoding='utf-8')
            if '[TODO:' in text:
                raise ValueError('Unfinished scaffold')
            for link in re.findall(r'\[[^\]]*\]\(([^)]+)\)', text):
                if re.match(r'^(?:https?://|#)', link):
                    continue
                if not (file.parent / link.split('#')[0]).exists():
                    raise ValueError('Missing local reference')
                links += 1
        plan = json.loads((root / 'assets/intent.example.json').read_text(encoding='utf-8'))
        if plan['status'] != 'draft' or any(v is not False for v in plan['authorization'].values()):
            raise ValueError('Example must not imply consent')
        from guard_config import validate
        guard = json.loads((root / 'assets/guard.example.json').read_text(encoding='utf-8'))
        validate(guard, ready=False)
        if guard['status'] != 'draft' or any(guard['authorization'].values()) or guard['broadband_ips'] or guard['region']:
            raise ValueError('Guard example must be an unconfigured draft')
        print(f'Skill metadata, draft intent and {links} local references validated.')
    except (OSError, ValueError, TypeError, KeyError, yaml.YAMLError):
        print('Skill validation failed; inspect local metadata and references.')
        return 1
    return 0


if __name__ == '__main__':
    sys.exit(main())
