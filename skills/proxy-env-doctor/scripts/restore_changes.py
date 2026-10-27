#!/usr/bin/env python3
"""Restore exact pre-change files; refuses to overwrite subsequent edits."""
import argparse
import json
from pathlib import Path
from change_bundle import restore


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = restore(args.bundle)
    except Exception:
        print('Restore failed; no source contents were printed. Compare subsequent edits or bundle state before retrying.')
        return 1
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
