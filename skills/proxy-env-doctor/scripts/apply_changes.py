#!/usr/bin/env python3
"""Apply prepared file changes only. Does not reload apps or operate Claude."""
import argparse
import json
from pathlib import Path
from change_bundle import apply


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--bundle', required=True, type=Path)
    parser.add_argument('--plan', required=True, type=Path)
    args = parser.parse_args()
    try:
        result = apply(args.bundle, args.plan)
    except Exception:
        print('Apply failed; no source contents were printed. Check private bundle and target state before retrying.')
        return 1
    print(json.dumps(result))
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
