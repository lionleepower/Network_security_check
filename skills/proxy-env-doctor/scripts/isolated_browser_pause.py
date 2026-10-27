"""Windows-only scoped browser pause probe; no app launch, credentials or UI input.

Probe freezes only an explicitly identified isolated Edge process tree for two
seconds and always attempts to resume it. This does not install a resident guard.
"""
import argparse
import ctypes
from ctypes import wintypes
import json
import os
from pathlib import Path
import re
import subprocess
import time


def flag(command, name):
    match = re.search(r'(?:^|\s)--' + re.escape(name) + r'=(?:"([^"]*)"|(\S+))(?=\s|$)', command or '')
    return (match[1] if match[1] is not None else match[2]) if match else None


def select(rows, profile, proxy_server='http://127.0.0.1:18081'):
    normalized = os.path.normcase(os.path.abspath(profile))
    roots = [r for r in rows if r.get('name', '').lower() == 'msedge.exe'
             and flag(r.get('command', ''), 'type') is None
             and flag(r.get('command', ''), 'user-data-dir') is not None
             and os.path.normcase(os.path.abspath(flag(r['command'], 'user-data-dir'))) == normalized
             and flag(r['command'], 'proxy-server') == proxy_server]
    if len(roots) != 1:
        raise ValueError('Exactly one verified isolated root required')
    root = roots[0]
    chosen = {root['pid']}
    for _ in range(len(rows)):
        additions = {r['pid'] for r in rows if r.get('parent') in chosen and r.get('name', '').lower() == 'msedge.exe'}
        if additions <= chosen:
            break
        chosen |= additions
    # A second independent browser root is never added merely by executable name.
    return root['pid'], [r for r in rows if r['pid'] in chosen]


def inventory(profile):
    code = r'''
$taskProfile=([Console]::In.ReadToEnd() | ConvertFrom-Json).profile
$taskRows=@(Get-CimInstance Win32_Process -Filter "Name='msedge.exe'" | ForEach-Object {
  [pscustomobject]@{pid=[int]$_.ProcessId;parent=[int]$_.ParentProcessId;name=$_.Name;created=$_.CreationDate.ToFileTimeUtc();command=$(if($_.CommandLine -and $_.CommandLine.Contains($taskProfile)){$_.CommandLine}else{''})}
})
ConvertTo-Json -InputObject $taskRows -Compress
'''
    result = subprocess.run(['powershell.exe', '-NoProfile', '-Command', code], input=json.dumps({'profile':str(profile)}),
                            text=True, capture_output=True, check=True, timeout=20)
    return json.loads(result.stdout)


def probe(profile):
    if os.name != 'nt':
        raise ValueError('Windows required')
    if not profile.is_absolute() or profile.name != 'claude-isolated-browser' or profile.parent.name != 'io.github.clash-verge-rev.clash-verge-rev':
        raise ValueError('Only the dedicated profile below the discovered client root is supported')
    profile = profile.resolve(strict=True)
    rows = inventory(profile)
    root, targets = select(rows, profile)
    kernel = ctypes.WinDLL('kernel32', use_last_error=True)
    native = ctypes.WinDLL('ntdll')
    kernel.OpenProcess.argtypes = [wintypes.DWORD,wintypes.BOOL,wintypes.DWORD]
    kernel.OpenProcess.restype = wintypes.HANDLE
    kernel.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)]*4
    kernel.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE,wintypes.DWORD,wintypes.LPWSTR,ctypes.POINTER(wintypes.DWORD)]
    for name in ['NtSuspendProcess','NtResumeProcess']:
        getattr(native,name).argtypes=[wintypes.HANDLE]
        getattr(native,name).restype=ctypes.c_long

    def times(handle):
        values=[wintypes.FILETIME() for _ in range(4)]
        if not kernel.GetProcessTimes(handle,*[ctypes.byref(v) for v in values]):
            raise OSError('Process time query failed')
        return [(v.dwHighDateTime<<32)|v.dwLowDateTime for v in values]

    handles, frozen, resumed = [], [], []
    result={'test':'two-second-scoped-pause','synthetic_trigger':True,'scope':'dedicated Edge tree only',
            'target_count':len(targets),'unrelated_edge_count':len(rows)-len(targets),'claude_target_count':0}
    try:
        # Pin process handles and check creation identities before any suspension.
        for row in sorted(targets,key=lambda r:r['pid']!=root):
            handle=kernel.OpenProcess(0x1000|0x0800,False,row['pid'])
            if not handle:
                raise OSError('Target changed or access unavailable')
            handles.append((row,handle))
            buffer=ctypes.create_unicode_buffer(32768);size=wintypes.DWORD(len(buffer))
            if not kernel.QueryFullProcessImageNameW(handle,0,buffer,ctypes.byref(size)) or Path(buffer.value).name.lower()!='msedge.exe':
                raise ValueError('Unexpected process executable')
            if abs(times(handle)[0]-row['created'])>=10:
                raise ValueError('PID creation identity changed')
        # Freeze root first; it can no longer create more browser child processes.
        for row,handle in handles:
            if native.NtSuspendProcess(handle)<0:
                raise OSError('Suspend failed')
            frozen.append((row,handle))
        # Detect a process-tree change during discovery instead of claiming coverage.
        _,current=select(inventory(profile),profile)
        if {r['pid'] for r in current}!={r['pid'] for r in targets}:
            raise ValueError('Process tree changed; probe must be repeated')
        cpu_before=[times(handle)[2:] for _,handle in frozen]
        time.sleep(2)
        cpu_after=[times(handle)[2:] for _,handle in frozen]
        result.update({'suspend_calls_succeeded':len(frozen),'cpu_times_unchanged':cpu_before==cpu_after})
    finally:
        for row,handle in reversed(frozen):
            if native.NtResumeProcess(handle)>=0:
                resumed.append(row['pid'])
        for _,handle in handles:
            kernel.CloseHandle(handle)
        result['resume_calls_succeeded']=len(resumed)
        if len(resumed)!=len(frozen):
            raise RuntimeError('Resume incomplete: stop and report recovery required')
    result['passed']=bool(frozen) and len(resumed)==len(targets) and result.get('cpu_times_unchanged') is True
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--profile',required=True,type=Path)
    parser.add_argument('--output',required=True,type=Path)
    args=parser.parse_args()
    try:
        if args.output.exists():
            raise ValueError('Choose a new evidence path')
        result=probe(args.profile)
        with args.output.open('x',encoding='utf-8') as stream:
            json.dump(result,stream,indent=2)
        print(json.dumps(result))
    except Exception as error:
        print('Scoped pause probe failed; no commands, credentials or process details printed. '+('Resume incomplete; recovery required.' if 'Resume incomplete' in str(error) else 'Inspect result before continuing.'))
        raise SystemExit(1)
