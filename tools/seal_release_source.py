#!/usr/bin/env python3
"""Create a deterministic ZIP from source in a verified directory."""
import argparse
import hashlib
import os
import sys
import zipfile
from pathlib import Path
sys.dont_write_bytecode = True
from verify_release_manifest import verify

def seal(root, destination):
    verify(root)
    base = root.name
    files = sorted(p for p in root.rglob('*') if p.is_file() and '.git' not in p.relative_to(root).parts)
    with zipfile.ZipFile(destination, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as z:
        for path in files:
            rel = path.relative_to(root).as_posix()
            zi = zipfile.ZipInfo(base + '/' + rel, date_time=(2026, 10, 9, 0, 0, 0))
            zi.compress_type = zipfile.ZIP_DEFLATED
            zi.external_attr = (0o100644 << 16)
            z.writestr(zi, path.read_bytes(), compress_type=zipfile.ZIP_DEFLATED, compresslevel=9)
    return hashlib.sha256(destination.read_bytes()).hexdigest()

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('destination')
    parser.add_argument('--source', default='.')
    args = parser.parse_args()
    root = Path(args.source).resolve()
    dest = Path(args.destination).resolve()
    if not dest.parent.is_dir() or dest.is_relative_to(root):
        print('refusing destination inside source or missing directory', file=sys.stderr)
        sys.exit(2)
    digest = seal(root, dest)
    print(f"PASS ZIP SHA256 {digest}")
