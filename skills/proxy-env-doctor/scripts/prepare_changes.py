#!/usr/bin/env python3
"""Prepare a private immutable-by-checksum bundle; never modifies original files."""
import argparse
import json
from pathlib import Path
from change_bundle import prepare


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plan', required=True, type=Path)
    parser.add_argument('--changes', required=True, type=Path)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--core', required=True, type=Path)
    parser.add_argument('--core-config', required=True, type=Path)
    parser.add_argument('--working-directory', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = prepare(args.plan, args.changes, args.bundle, args.core, args.core_config, args.working_directory)
    except Exception:
        print('Preparation failed; no source contents were printed.')
        return 1
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
