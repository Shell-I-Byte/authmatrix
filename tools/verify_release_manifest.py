#!/usr/bin/env python3
"""Strict standalone source integrity verifier, stdlib only."""
import argparse
import hashlib
import json
import sys
from pathlib import Path

MANIFEST = "SOURCE_MANIFEST_SHA256.json"
IGNORE = {".git"}

def list_files(root):
    result = {}
    for p in root.rglob("*"):
        relative = p.relative_to(root).as_posix()
        if any(x in IGNORE for x in p.relative_to(root).parts):
            continue
        if p.is_symlink():
            raise ValueError("symlink forbidden: " + relative)
        if not p.is_file():
            continue
        if relative == MANIFEST:
            continue
        if "__pycache__" in p.parts or p.suffix == ".pyc":
            raise ValueError("generated unlisted file: " + relative)
        result[relative] = hashlib.sha256(p.read_bytes()).hexdigest()
    return dict(sorted(result.items()))

def verify(root):
    raw = (root / MANIFEST).read_bytes()
    m = json.loads(raw)
    if set(m) != {"algorithm", "files"} or m["algorithm"] != "SHA-256":
        raise ValueError("invalid manifest")
    expected = m["files"]
    actual = list_files(root)
    if actual != expected:
        missing = sorted(set(expected) - set(actual))
        extra = sorted(set(actual) - set(expected))
        modified = sorted(k for k in set(actual) & set(expected) if actual[k] != expected[k])
        raise ValueError(f"manifest mismatch: missing={missing} extra={extra} modified={modified}")
    return len(actual)

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--source", default=".")
    p.add_argument("--sealed", action="store_true")
    args = p.parse_args()
    try:
        n = verify(Path(args.source).resolve())
        print(f"PASS: {n}/{n} source SHA256 entries, strict exact membership")
    except (OSError, ValueError, KeyError, TypeError) as exc:
        print(f"FAIL: {exc}", file=sys.stderr)
        sys.exit(1)
