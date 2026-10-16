#!/usr/bin/env python3
"""Native cross-platform CLI acceptance: synthetic inputs, no external network.

This script is suitable for native Linux, macOS and Windows runners. Running it
on Linux is NOT evidence of execution on macOS or Windows.
"""
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]


def input_doc(status=403, control=False, approved=True, expected='deny'):
    return {
        'schema': 'authmatrix.matrix/v1',
        'authorization': {'approved': approved, 'origin': 'synthetic', 'scope': 'LOCAL_ONLY_SECRET'},
        'cases': [{'id': 'SECRET_CASE_193', 'kind': 'horizontal', 'expected': expected,
                   'observed_status': status, 'positive_control_confirmed': control}],
    }


def main():
    completed = 0
    with tempfile.TemporaryDirectory(prefix='authmatrix-native-') as tmp:
        home = Path(tmp)
        binary = home / ('authmatrix.exe' if os.name == 'nt' else 'authmatrix')
        subprocess.run(['go', 'build', '-trimpath', '-buildvcs=false', '-o', str(binary),
                        './cmd/authmatrix'], cwd=ROOT, check=True)

        def run_file(name, doc, expected_code, expected_verdict=None):
            nonlocal completed
            source = home / (name + '.json')
            source.write_text(json.dumps(doc, separators=(',', ':')), encoding='utf8')
            p = subprocess.run([str(binary), 'evaluate', '-in', str(source)],
                               cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
            assert p.returncode == expected_code, (name, p.returncode, p.stderr[:100])
            if expected_verdict is None:
                assert p.stdout == b'', name
            else:
                report = json.loads(p.stdout)
                assert report['schema'] == 'authmatrix.result/v1'
                assert report['evidence'][0]['verdict'] == expected_verdict
                assert b'SECRET_CASE_193' not in p.stdout
                assert b'LOCAL_ONLY_SECRET' not in p.stdout
            completed += 1
            return p.stdout

        check_version = subprocess.run([str(binary), 'version'], cwd=ROOT,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=15)
        assert check_version.returncode == 0 and check_version.stdout.strip() == b'v0.1.0-rc10'
        completed += 1
        baseline = run_file('denied403', input_doc(), 0, 'match')
        run_file('negative_unauthorized', input_doc(approved=False), 2)
        run_file('potential_bypass', input_doc(status=200), 1, 'potential-bypass')
        run_file('positive_control404', input_doc(status=404, control=True), 0, 'match')
        run_file('unverified404', input_doc(status=404), 0, 'inconclusive')
        run_file('allow2xx', input_doc(status=204, expected='allow'), 0, 'match')
        for i in range(3):
            again = run_file('deterministic_'+str(i), input_doc(), 0, 'match')
            assert again == baseline
        for name, value in [('invalid_status', '999'), ('fraction_status', '200.01'),
                            ('null_status', 'null')]:
            doc = input_doc()
            doc['cases'][0]['observed_status'] = {'invalid_status': 999, 'fraction_status': 200.01,
                                                  'null_status': None}[name]
            run_file(name, doc, 2)
    print(f'PASS: {completed} portable native CLI assertions; host={os.name}')


if __name__ == '__main__':
    main()
