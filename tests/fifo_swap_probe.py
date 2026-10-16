#!/usr/bin/env python3
"""Local-only synthetic FIFO/regular-file race probe; never sends network requests."""
import argparse, ctypes, json, os, pathlib, subprocess, tempfile, threading, time
p = argparse.ArgumentParser()
p.add_argument('binary'); p.add_argument('--count',type=int,default=100); p.add_argument('--timeout',type=float,default=.55)
a=p.parse_args()
libc=ctypes.CDLL(None, use_errno=True)
libc.renameat2.argtypes=[ctypes.c_int,ctypes.c_char_p,ctypes.c_int,ctypes.c_char_p,ctypes.c_uint]
libc.renameat2.restype=ctypes.c_int
with tempfile.TemporaryDirectory(prefix='am-fifo-race-') as t:
    root=pathlib.Path(t); reg=root/'candidate'; alt=root/'alternate'
    reg.write_text(json.dumps({'schema':'authmatrix.matrix/v1','authorization':{'approved':True,'origin':'synthetic','scope':'local'},'cases':[{'id':'only','kind':'horizontal','expected':'deny','observed_status':403}]}))
    os.mkfifo(alt)
    stop=threading.Event(); errors=[]; flips=[0]
    def swapper():
        x=os.fsencode(reg);y=os.fsencode(alt)
        while not stop.is_set():
            if libc.renameat2(-100,x,-100,y,2)!=0:
                errors.append(ctypes.get_errno());break
            flips[0]+=1
    thread=threading.Thread(target=swapper,daemon=True); thread.start()
    status={'passed':0,'rejected':0,'hang':0,'other':0,'attempts':a.count}
    t0=time.monotonic()
    for k in range(a.count):
        try:
            r=subprocess.run([a.binary,'evaluate','-in',str(reg)],capture_output=True,timeout=a.timeout)
            if r.returncode==0:status['passed']+=1
            elif r.returncode==2:status['rejected']+=1
            else:status['other']+=1
        except subprocess.TimeoutExpired:
            status['hang']+=1
            if status['hang']>=2:break
    stop.set();thread.join(timeout=1)
    status.update(flips=flips[0],errors=errors,elapsed_s=round(time.monotonic()-t0,3))
    print(json.dumps(status,sort_keys=True))
    if errors:returncode=4
    elif status['hang']:returncode=3
    elif status['other']:returncode=5
    else:returncode=0
    raise SystemExit(returncode)
