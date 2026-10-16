#!/usr/bin/env python3
"""Validate complete AuthMatrix source ZIP membership and hashes BEFORE extraction.

This checks the *container*, unlike verify_release_manifest.py, which checks
only a previously extracted source directory. Standard-library only.
"""
import argparse
import hashlib
import json
import re
import stat
import sys
import zipfile
from pathlib import Path

MAX_MEMBERS = 4096
MAX_MEMBER_BYTES = 8 << 20
MAX_TOTAL_BYTES = 64 << 20
MANIFEST = 'SOURCE_MANIFEST_SHA256.json'
# Win32 device basenames are reserved even when a file extension is present.
# Win32 strips trailing periods/spaces from ordinary paths, allowing collisions
# even when no two ZIP members have exactly the same name. The path-component
# alphabet below already rejects spaces and non-ASCII device-name variants.
WINDOWS_DEVICES = {'CON', 'PRN', 'AUX', 'NUL'} | {
    f'{prefix}{index}' for prefix in ('COM', 'LPT') for index in range(1, 10)
}


def portable_part(part: str) -> bool:
    if not re.fullmatch(r'[A-Za-z0-9_.-]{1,128}', part):
        return False
    if part in {'.', '..'} or part.endswith('.'):
        return False
    return part.split('.', 1)[0].upper() not in WINDOWS_DEVICES


def verify(archive: Path, root: str) -> int:
    if not portable_part(root):
        raise ValueError('unsafe source root')
    with zipfile.ZipFile(archive) as z:
        entries = z.infolist()
        if not entries or len(entries) > MAX_MEMBERS:
            raise ValueError('invalid archive member count')
        files = {}
        folded_files = set()
        canonical_directories = set()
        directory_spellings = {}
        total = 0
        for entry in entries:
            name = entry.filename
            if '\\' in name or '\x00' in name or '\r' in name or '\n' in name:
                raise ValueError('invalid archive member path')
            if not name.startswith(root + '/'):
                raise ValueError('member outside verified source directory')
            rel = name[len(root) + 1:]
            parts = rel.split('/')
            if not rel or any(p in {'', '.', '..'} for p in parts):
                raise ValueError('invalid path segment')
            if not all(portable_part(p) for p in parts):
                raise ValueError('nonportable source member path')
            # Validate the *hierarchy*, not only complete member names. A
            # checksummed archive can otherwise contain LICENSE/child.txt
            # while LICENSE is itself a regular file, or both docs/ and DOCS/
            # on a case-insensitive target filesystem. Both are unextractable
            # or ambiguous even though every individual SHA-256 is correct.
            canonical = '/'.join(p.casefold() for p in parts)
            if canonical in folded_files or canonical in canonical_directories:
                raise ValueError('duplicate member or file/directory conflict')
            for i in range(1, len(parts)):
                parent_name = '/'.join(parts[:i])
                parent_key = parent_name.casefold()
                if parent_key in folded_files:
                    raise ValueError('parent is an archive file')
                prior = directory_spellings.get(parent_key)
                if prior is not None and prior != parent_name:
                    raise ValueError('case-colliding ancestor directories')
                directory_spellings[parent_key] = parent_name
                canonical_directories.add(parent_key)
            folded_files.add(canonical)
            mode = (entry.external_attr >> 16) & 0o177777
            kind = stat.S_IFMT(mode)
            if entry.is_dir() or kind not in {stat.S_IFREG, 0}:
                raise ValueError('nonregular archive member')
            if entry.flag_bits & 1 or entry.compress_type not in {zipfile.ZIP_STORED, zipfile.ZIP_DEFLATED}:
                raise ValueError('unsupported archive member encryption or compression')
            if entry.file_size > MAX_MEMBER_BYTES or entry.file_size < 0:
                raise ValueError('member too large')
            total += entry.file_size
            if total > MAX_TOTAL_BYTES:
                raise ValueError('total archive size too large')
            files[rel] = entry
        if MANIFEST not in files:
            raise ValueError('missing source manifest')
        raw_manifest = z.read(files[MANIFEST])
        manifest = json.loads(raw_manifest)
        if not isinstance(manifest, dict) or set(manifest) != {'algorithm', 'files'} or manifest['algorithm'] != 'SHA-256':
            raise ValueError('invalid source manifest')
        expected = manifest['files']
        if not isinstance(expected, dict) or set(files) != set(expected) | {MANIFEST}:
            raise ValueError('archive membership differs from manifest')
        for rel, digest in expected.items():
            if not isinstance(digest, str) or not re.fullmatch(r'[0-9a-f]{64}', digest):
                raise ValueError('invalid manifest hash')
            data = z.read(files[rel])
            if hashlib.sha256(data).hexdigest() != digest:
                raise ValueError('archive source hash mismatch')
        return len(expected)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('archive', type=Path)
    p.add_argument('--root', required=True, help='the sole source directory name in the archive')
    a = p.parse_args()
    try:
        n = verify(a.archive, a.root)
        print(f'PASS: archive membership and {n}/{n} source SHA256 entries')
        return 0
    except (OSError, ValueError, TypeError, KeyError, json.JSONDecodeError, zipfile.BadZipFile, EOFError, RuntimeError) as exc:
        print(f'FAIL: source archive rejected ({type(exc).__name__})', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())
