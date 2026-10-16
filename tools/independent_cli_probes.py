#!/usr/bin/env python3
"""Independent CLI black-box probes; zero external targets; stdlib only."""
import concurrent.futures
import json
import os
from pathlib import Path
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[1]
COUNT = 0

def check(result, code, phrase=None):
    global COUNT
    COUNT += 1
    if result.returncode != code or (phrase and phrase not in result.stdout):
        raise AssertionError(f"probe {COUNT}: rc={result.returncode} expected {code}, stdout={result.stdout[:100]!r}, stderr={result.stderr[:100]!r}")
    if b'FAKE-PASS' in result.stderr or b'\x1b' in result.stderr:
        raise AssertionError('untrusted log control emitted')

def sample(status=200, expected='deny', approved=True, control=False):
    return json.dumps({'schema':'authmatrix.matrix/v1', 'authorization':{'approved':approved,'origin':'synthetic','scope':'fixture'}, 'cases':[{'id':'caseSecret', 'kind':'horizontal','expected':expected,'observed_status':status,'positive_control_confirmed':control}]}).encode()

def main():
    with tempfile.TemporaryDirectory(prefix='authmatrix-probe-') as tmp:
        d = Path(tmp)
        binary = d / 'authmatrix'
        subprocess.run(['go','build','-trimpath','-buildvcs=false','-o',str(binary),'./cmd/authmatrix'], cwd=ROOT, check=True, env={**os.environ,'GOTOOLCHAIN':'local','GOPROXY':'off'})
        def exe(args):
            return subprocess.run([str(binary), *args], cwd=ROOT, capture_output=True)
        check(exe(['version']),0, b'v0.1.0-rc10')
        # Normal help is not an invalid argument; invalid flags still must fail.
        for args in (['-h'], ['--help'], ['-help'], ['evaluate','-h'],
                     ['evaluate','--help'], ['evaluate','-help']):
            help_result=exe(args)
            check(help_result,0,b'usage: authmatrix')
            if help_result.stderr:
                raise AssertionError('help must not write errors to stderr')
        for status, expected, control, code, verdict in [
            (200,'deny',False,1,'potential-bypass'),(201,'deny',False,1,'potential-bypass'),(299,'deny',False,1,'potential-bypass'),
            (200,'allow',False,0,'match'),(204,'allow',False,0,'match'),(299,'allow',False,0,'match'),
            (401,'deny',False,0,'match'),(403,'deny',False,0,'match'),(404,'deny',False,0,'inconclusive'),
            (404,'deny',True,0,'match'),(302,'deny',False,0,'inconclusive'),(429,'deny',False,0,'inconclusive'),
            (500,'deny',False,0,'inconclusive'),(503,'allow',False,0,'inconclusive'),(100,'allow',False,0,'inconclusive'),
        ]:
            input_path = d / f'input-{status}-{expected}-{int(control)}.json'
            input_path.write_bytes(sample(status,expected,True,control))
            r = exe(['evaluate','-in',str(input_path)])
            check(r,code,verdict.encode())
            if b'caseSecret' in r.stdout or b'fixture' in r.stdout:
                raise AssertionError('private ID or scope leaked')
        # Go encoding/json/v1 otherwise accepts caseless struct keys, which
        # can bypass strict schema/authorization semantics in conflicting keys.
        for key in ('Approved', 'APPROVED', 'Kind', 'Origin', 'Cases', 'Observed_Status'):
            obj=json.loads(sample())
            if key in ('Cases',):
                obj[key]=obj['cases']
            elif key in ('Origin',):
                obj['authorization'][key]=obj['authorization']['origin']
            elif key in ('Observed_Status',):
                obj['cases'][0][key]=obj['cases'][0]['observed_status']
            elif key in ('Kind',):
                obj['cases'][0][key]=obj['cases'][0]['kind']
            else:
                obj['authorization'][key]=True
            case_file=d/('casefold-'+str(len(str(obj)))+'-'+key+'.json')
            case_file.write_text(json.dumps(obj))
            check(exe(['evaluate','-in',str(case_file)]),2)
        # Explicit FALSE approval must never be promoted by a later alias.
        obj=json.loads(sample())
        obj['authorization']['approved']=False
        obj['authorization']['Approved']=True
        case_file=d/'casefold-authorization.json'
        case_file.write_text(json.dumps(obj))
        check(exe(['evaluate','-in',str(case_file)]),2)
        p=d/'raw.json'
        bads=[
            (b'not json','malformed'),
            (b'{"schema":"x","schema":"authmatrix.matrix/v1"}','duplicate-root'),
            (b'{"authorization":{"scope":"a","scope":"b"}}','duplicate-nested'),
            (b'\xff\xff','invalid-utf8'),
            (sample(200,'deny',False),'no approval'),
            (sample(99),'invalid-low-status'),
            (sample(600),'invalid-high-status'),
            (sample().replace(b'"schema": "authmatrix.matrix/v1"',b'"schema":"bad"'),'bad-schema'),
            (sample()+b'{}','trailing-json'),
            (sample().replace(b'"id": "caseSecret"',b'"id":"case\\nSecret"'),'control-id'),
            (b'x'*(2**20+1),'oversized'),
        ]
        for data,name in bads:
            p.write_bytes(data)
            check(exe(['evaluate','-in',str(p)]),2)
        p.write_bytes(sample())
        check(exe(['evaluate','-in',str(p),'-not-valid=\n\x1b[0mFAKE-PASS']),2)
        check(exe(['evaluate','-in','\n\x1b[0mFAKE-PASS']),2)
        check(exe(['evaluate','-in',str(d/'nonexistent')]),2)
        report=d/'result.json'
        check(exe(['evaluate','-in',str(p),'-out',str(report)]),1)
        if not report.is_file() or (report.stat().st_mode & 0o077):raise AssertionError('output not private mode 0600')
        check(exe(['evaluate','-in',str(p),'-out',str(report)]),2)
        check(exe(['evaluate','-in',str(p),'-out',str(p)]),2)
        symlink=d/'symlink.json';symlink.symlink_to(p)
        check(exe(['evaluate','-in',str(symlink)]),2)
        # This was a candidate bug class, but direct FIFO inputs were
        # correctly rejected even in RC1, unlike some sister tools.
        if hasattr(os, 'mkfifo'):
            fifo=d/'input.fifo'
            os.mkfifo(fifo)
            check(exe(['evaluate','-in',str(fifo)]),2)
            fifo_link=d/'fifo-symlink'
            fifo_link.symlink_to(fifo)
            check(exe(['evaluate','-in',str(fifo_link)]),2)
        baseline=exe(['evaluate','-in',str(p)]).stdout
        def repeated(_):
            r=exe(['evaluate','-in',str(p)]);return r.returncode==1 and r.stdout==baseline
        with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
            rs=list(pool.map(repeated,range(8)))
        for good in rs:
            if not good:raise AssertionError('concurrent deterministic output mismatch')
            COUNT_PLUS()
    print(f"PASS: {COUNT} independent black-box CLI assertions")

def COUNT_PLUS():
    global COUNT
    COUNT += 1
if __name__ == '__main__':main()
