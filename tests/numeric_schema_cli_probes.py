#!/usr/bin/env python3
"""Independent standard-library black-box regression for JSON Schema numeric integers.
Only local synthetic files. Executable is supplied as the first argument.
"""
import json
from pathlib import Path
import subprocess
import sys
import tempfile

BIN = str(Path(sys.argv[1]).resolve()) if len(sys.argv) > 1 else None
if BIN is None:
    raise SystemExit('usage: numeric_schema_cli_probes.py /path/to/authmatrix')

VALID = {
    '100': 100, '100.0': 100, '1e2': 100, '1E+02': 100,
    '200': 200, '200.0': 200, '2e2': 200, '2E+02': 200,
    '200.0000': 200, '0.0002e6': 200, '2.000e2': 200,
    '400.0': 400, '403.000000': 403, '404E0': 404, '599.0': 599,
    '5.99e2': 599, '59.9e1': 599, '200e-0': 200,
    '1e+00000002': 100,
    '200.00000000000000000000000000000000': 200,
}
INVALID = [
    '99', '99.0', '600', '600.0', '200.1', '200.00001',
    '200.000000000000000000000000000000001', '599.1',
    '-200', '-200.0', '2e1', '2e-2', '0', '0.0',
    '2e99999999999999999999999999', '2e-99999999999999999',
    'null', 'true', 'false', '"200"',
]

with tempfile.TemporaryDirectory(prefix='authmatrix-numeric-') as td:
    path = Path(td) / 'matrix.json'
    count = 0
    for token, value in list(VALID.items()) + [(x, None) for x in INVALID]:
        raw = ( '{"schema":"authmatrix.matrix/v1",'
          '"authorization":{"approved":true,"origin":"synthetic","scope":"example"},'
          '"cases":[{"id":"localCase","kind":"horizontal","expected":"deny",'
          '"observed_status":' + token + '}]}' ).encode()
        path.write_bytes(raw)
        result = subprocess.run([BIN, 'evaluate', '-in', str(path)], capture_output=True, timeout=5)
        count += 1
        if value is not None:
            if result.returncode not in (0, 1):
                raise AssertionError(f'{token}: expected accepted, exit {result.returncode}')
            report = json.loads(result.stdout)
            if report['evidence'][0]['observed_status'] != value:
                raise AssertionError(f'{token}: status was not normalized correctly')
            if report['input_sha256'] == '' or b'localCase' in result.stdout:
                raise AssertionError(f'{token}: privacy/provenance check failed')
        else:
            if result.returncode != 2 or result.stdout:
                raise AssertionError(f'{token}: should be rejected, got {result.returncode}')
    print(f'PASS: {count}/{count} independent numeric-schema CLI assertions')
