#!/usr/bin/env python3
"""Local-only Linux synthetic adversarial ancestor swap; does not contact networks."""
import argparse, ctypes, os, pathlib, subprocess, tempfile, threading

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('binary'); ap.add_argument('--count',type=int,default=250); args=ap.parse_args()
    if not 1 <= args.count <= 2000: raise SystemExit('invalid count')
    binary=str(pathlib.Path(args.binary).resolve())
    libc=ctypes.CDLL(None,use_errno=True)
    libc.renameat2.argtypes=(ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint)
    libc.renameat2.restype=ctypes.c_int
    with tempfile.TemporaryDirectory(prefix='authmatrix-ancestor-') as td:
        root=pathlib.Path(td)
        anchor=root/'anchor'; alias=root/'alias'; outside=root/'outside'
        (anchor/'parent').mkdir(parents=True)
        (outside/'parent').mkdir(parents=True)
        alias.symlink_to(outside, target_is_directory=True)
        src=root/'input.json'
        src.write_text('{"schema":"authmatrix.matrix/v1","authorization":{"approved":true,"origin":"synthetic","scope":"local-fixture"},"cases":[{"id":"case1","kind":"horizontal","expected":"deny","observed_status":200}]}')
        errors=[]; count=[0]
        stop=threading.Event()
        def thread_fn():
            while not stop.is_set():
                res=libc.renameat2(-100,os.fsencode(anchor),-100,os.fsencode(alias),2)
                if res != 0:
                    errors.append(ctypes.get_errno());break
                count[0]+=1
        thread=threading.Thread(target=thread_fn,daemon=True);thread.start()
        wins=0
        try:
            for i in range(args.count):
                r=subprocess.run([binary,'evaluate','-in',str(src),'-out',str(anchor/'parent'/f'evidence_{i}.json')],capture_output=True,timeout=3)
                if r.returncode == 1: wins+=1
                elif r.returncode != 2: raise RuntimeError(f'bad exit {r.returncode} stderr={r.stderr[:100]!r}')
        finally:
            stop.set();thread.join(timeout=3)
        escaped=list((outside/'parent').glob('evidence_*.json'))
        safe=[]
        for directory in [anchor,alias]:
            if directory.is_dir() and not directory.is_symlink() and (directory/'parent').is_dir():safe+=list((directory/'parent').glob('evidence_*.json'))
        print(f'attempts={args.count} successful={wins} swaps={count[0]} OUTSIDE={len(escaped)} own={len(safe)} errors={errors}')
        if escaped:
            print('FAIL: output escaped through a swapped symlink ancestor')
            return 1
        if errors or wins<1 or count[0]<10:
            print('INCONCLUSIVE: insufficient exercise');return 2
        print('PASS: no report in outside directory');return 0
if __name__=='__main__':raise SystemExit(main())
