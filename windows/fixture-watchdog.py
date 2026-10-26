"""Disposable CI only: bound newly-created fixture processes holding WFP.

Never runs on an owner PC. It retains a verified process handle, never kills by
PID/name alone, and a forced termination always makes acceptance fail.
"""
import ctypes as C
from ctypes import wintypes as W
import hashlib, json, os, sys, time
from pathlib import Path

assert sys.platform == 'win32'
assert os.environ.get('GITHUB_ACTIONS') == 'true'
assert os.environ.get('RUNNER_ENVIRONMENT') == 'github-hosted'
assert os.environ.get('GITHUB_REPOSITORY') == '2njz45z86r-commits/vpn013-wg-ios'
root, go_work, client = map(lambda p: Path(p).resolve(), sys.argv[1:4])
assert root.is_dir() and go_work.is_dir()
assert go_work.parent==root.parent and go_work.name==root.name+'-owned-go-work'
assert client.name == 'VPN013WG.exe' and client.is_file()
client_hash = hashlib.sha256(client.read_bytes()).hexdigest()
os.umask(0o077)
adv = C.WinDLL('advapi32', use_last_error=True)
kernel = C.WinDLL('kernel32', use_last_error=True)

class Status(C.Structure):
    _fields_ = [(n, W.DWORD) for n in ('type','state','accepts','win32','specific','checkpoint','hint','pid','flags')]

class Entry(C.Structure):
    _fields_ = [('name',W.LPWSTR),('display',W.LPWSTR),('status',Status)]

adv.OpenSCManagerW.argtypes = [W.LPCWSTR,W.LPCWSTR,W.DWORD]
adv.OpenSCManagerW.restype = W.HANDLE
adv.EnumServicesStatusExW.argtypes = [W.HANDLE,W.DWORD,W.DWORD,W.DWORD,C.c_void_p,W.DWORD,C.POINTER(W.DWORD),C.POINTER(W.DWORD),C.POINTER(W.DWORD),W.LPCWSTR]
adv.EnumServicesStatusExW.restype = W.BOOL
adv.CloseServiceHandle.argtypes = [W.HANDLE]
kernel.OpenProcess.argtypes = [W.DWORD,W.BOOL,W.DWORD]
kernel.OpenProcess.restype = W.HANDLE
kernel.QueryFullProcessImageNameW.argtypes = [W.HANDLE,W.DWORD,W.LPWSTR,C.POINTER(W.DWORD)]
kernel.WaitForSingleObject.argtypes = [W.HANDLE,W.DWORD]
kernel.WaitForSingleObject.restype = W.DWORD
kernel.TerminateProcess.argtypes = [W.HANDLE,W.UINT]
kernel.CloseHandle.argtypes = [W.HANDLE]
scm = adv.OpenSCManagerW(None,None,4)  # enumerate only, never service control
assert scm, 'Watchdog SCM census unavailable'

def census():
    needed,count,resume = W.DWORD(),W.DWORD(),W.DWORD()
    buffer = C.create_string_buffer(2*1024*1024)
    ok = adv.EnumServicesStatusExW(scm,0,0x30,3,buffer,len(buffer),C.byref(needed),C.byref(count),C.byref(resume),None)
    assert ok and count.value<=4096 and resume.value==0, 'Incomplete watchdog census'
    entries = C.cast(buffer,C.POINTER(Entry))
    return {entries[i].name:int(entries[i].status.pid) for i in range(count.value)}

baseline = set(census())
tracked = {}
forced = []
observed = []
started = time.monotonic()

def record():
    report = {'scope':'disposable hosted CI fixture cleanup only','baselineDefinitions':len(baseline),
              'observed':observed,'forced':forced,'elapsedSeconds':round(time.monotonic()-started,1)}
    pending = root/'fixture-watchdog.pending'
    pending.write_text(json.dumps(report,indent=2),encoding='utf-8')
    os.replace(pending,root/'fixture-watchdog.json')

def image(handle):
    buffer=C.create_unicode_buffer(32768);size=W.DWORD(len(buffer))
    assert kernel.QueryFullProcessImageNameW(handle,0,buffer,C.byref(size)), 'Cannot identify candidate process'
    return Path(buffer.value).resolve()

try:
    record()
    (root/'fixture-watchdog.ready').write_text('ready',encoding='ascii')
    while True:
        stopping=(root/'fixture-watchdog.stop').exists() or time.monotonic()-started>1300
        for name,pid in census().items():
            if name in baseline or not pid or name in tracked:
                continue
            if not (name.startswith('R013') or ('Tunnel$R013' in name)):
                continue
            handle=kernel.OpenProcess(0x1000|0x1|0x100000,False,pid)
            if not handle:
                continue  # already exited or inaccessible: never widen access
            try:
                path=image(handle)
                own_test=path.is_relative_to(go_work) and path.name in ('r013gate.test.exe','firewall.test.exe','tunnel.test.exe')
                own_client=path==client and hashlib.sha256(path.read_bytes()).hexdigest()==client_hash
                if not (own_test or own_client):
                    kernel.CloseHandle(handle);continue
            except (OSError,AssertionError):
                kernel.CloseHandle(handle);continue
            tracked[name]=(handle,pid,time.monotonic())
            observed.append({'service':name,'pid':pid,'image':path.name,'imageSHA256':hashlib.sha256(path.read_bytes()).hexdigest()})
        for name,(handle,pid,stamp) in list(tracked.items()):
            state=kernel.WaitForSingleObject(handle,0)
            if state==0:
                kernel.CloseHandle(handle);del tracked[name];continue
            assert state==258, 'Cannot read retained process state'
            if stopping or time.monotonic()-stamp>240:
                terminated=bool(kernel.TerminateProcess(handle,124))
                wait=int(kernel.WaitForSingleObject(handle,5000))
                forced.append({'service':name,'pid':pid,'reason':'cleanup' if stopping else '240s fixture deadline','terminated':terminated,'waitResult':wait})
                kernel.CloseHandle(handle);del tracked[name]
        record()
        if stopping:
            break
        time.sleep(2)
finally:
    for handle,_,_ in tracked.values():
        kernel.CloseHandle(handle)
    adv.CloseServiceHandle(scm)
    record()
raise SystemExit(1 if forced else 0)
