#!/usr/bin/env python3
"""Synthetic Linux-only adversarial rename exchange against CLI output parent.

Usage: python3 tests/parent_swap_output_probe.py /path/to/authmatrix --count 450
Only touches a self-created temporary local tree; never sends network traffic.
"""
import argparse
import ctypes
import os
import pathlib
import subprocess
import tempfile
import threading


def main():
    a = argparse.ArgumentParser()
    a.add_argument('binary')
    a.add_argument('--count', type=int, default=450)
    args = a.parse_args()
    binary = str(pathlib.Path(args.binary).resolve())
    if os.uname().sysname != 'Linux':
        raise SystemExit('SKIP: Linux renameat2 test only')
    if not 1 <= args.count <= 3000:
        raise SystemExit('FAIL: invalid bounded count')
    libc = ctypes.CDLL(None, use_errno=True)
    libc.renameat2.argtypes = (ctypes.c_int, ctypes.c_char_p, ctypes.c_int, ctypes.c_char_p, ctypes.c_uint)
    libc.renameat2.restype = ctypes.c_int
    with tempfile.TemporaryDirectory(prefix='authmatrix-parent-swap-') as temp:
        root = pathlib.Path(temp)
        parent = root / 'parent'
        other = root / 'other'
        outside = root / 'outside'
        parent.mkdir()
        outside.mkdir()
        other.symlink_to(outside, target_is_directory=True)
        source = root / 'valid.json'
        source.write_text('{"schema":"authmatrix.matrix/v1","authorization":{"approved":true,"origin":"synthetic","scope":"local-fixture"},"cases":[{"id":"case1","kind":"horizontal","expected":"deny","observed_status":200}]}')
        stop = threading.Event()
        errors = []
        swaps = [0]
        def exchange():
            while not stop.is_set():
                rc = libc.renameat2(-100, os.fsencode(parent), -100, os.fsencode(other), 2)
                if rc != 0:
                    errors.append(ctypes.get_errno())
                    break
                swaps[0] += 1
        thread = threading.Thread(target=exchange, daemon=True)
        thread.start()
        successes = 0
        try:
            for i in range(args.count):
                result = subprocess.run([binary, 'evaluate', '-in', str(source), '-out', str(parent / f'out_{i}.json')], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=3)
                if result.returncode == 1:
                    successes += 1
                elif result.returncode != 2:
                    raise RuntimeError(f'unexpected exit code {result.returncode} at {i}')
        finally:
            stop.set()
            thread.join(timeout=3)
        leaked = sorted(p.name for p in outside.iterdir())
        print(f'attempts={args.count} success={successes} exchanges={swaps[0]} outside_reports={len(leaked)} swap_errors={errors}')
        if leaked:
            print('FAIL: outputs appeared outside checked real parent; examples=' + ','.join(leaked[:5]))
            return 1
        if errors or swaps[0] < 10 or successes < 1:
            print('INCONCLUSIVE: swap not exercised adequately')
            return 2
        print('PASS: no outside writes during parent/symlink exchanges')
        return 0

if __name__ == '__main__':
    raise SystemExit(main())
