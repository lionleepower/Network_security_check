"""Persistent scoped Windows pause; only explicit resume releases it.

Journal survives caller termination. Ambiguous interruption during a native call
requires review, rather than guessing a suspension count and over-resuming.
"""
import ctypes
from ctypes import wintypes
import json
from pathlib import Path
from isolated_browser_pause import inventory, select
from guard_store import save


class Native:
    def __init__(self):
        self.k = ctypes.WinDLL('kernel32', use_last_error=True)
        self.n = ctypes.WinDLL('ntdll')
        self.k.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
        self.k.OpenProcess.restype = wintypes.HANDLE
        self.k.CloseHandle.argtypes = [wintypes.HANDLE]
        self.k.GetProcessTimes.argtypes = [wintypes.HANDLE] + [ctypes.POINTER(wintypes.FILETIME)] * 4
        self.k.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
        for name in ('NtSuspendProcess', 'NtResumeProcess'):
            getattr(self.n, name).argtypes = [wintypes.HANDLE]
            getattr(self.n, name).restype = ctypes.c_long

    def times(self, handle):
        fields = [wintypes.FILETIME() for _ in range(4)]
        if not self.k.GetProcessTimes(handle, *map(ctypes.byref, fields)):
            raise RuntimeError('process_query_failed')
        return [(v.dwHighDateTime << 32) | v.dwLowDateTime for v in fields]

    def open(self, row):
        handle = self.k.OpenProcess(0x1000 | 0x0800, False, row['pid'])
        if not handle:
            raise RuntimeError('process_unavailable')
        try:
            text = ctypes.create_unicode_buffer(32768); size = wintypes.DWORD(len(text))
            if not self.k.QueryFullProcessImageNameW(handle, 0, text, ctypes.byref(size)) or Path(text.value).name.lower() != 'msedge.exe':
                raise RuntimeError('wrong_executable')
            if abs(self.times(handle)[0] - row['created']) >= 10:
                raise RuntimeError('pid_reused')
            return handle
        except BaseException:
            self.close(handle)
            raise

    def close(self, handle):
        self.k.CloseHandle(handle)

    def pause(self, handle):
        if self.n.NtSuspendProcess(handle) < 0:
            raise RuntimeError('native_pause_failed')

    def resume(self, handle):
        if self.n.NtResumeProcess(handle) < 0:
            raise RuntimeError('native_resume_failed')


def pause(profile, journal_path, native=None, scan=inventory, scope=None):
    profile = Path(profile).resolve(strict=True)
    proxy_server = 'http://127.0.0.1:18081'
    if scope is not None:
        marker = json.loads((profile / '.proxy-env-doctor-scope.json').read_text(encoding='utf-8'))
        if marker != {'scope_id': scope['scope_id']} or Path(scope['profile']).resolve() != profile:
            raise ValueError('unregistered_profile')
        proxy_server = scope['proxy']
    elif profile.name != 'claude-isolated-browser' or profile.parent.name != 'io.github.clash-verge-rev.clash-verge-rev':
        raise ValueError('unexpected_profile')
    if journal_path.exists():
        old = json.loads(journal_path.read_text(encoding='utf-8'))
        if old['phase'] != 'resumed':
            if old['phase'] == 'paused':
                _, current = select(scan(profile), profile, proxy_server)
                identities = {(r['pid'], r['created']) for r in current}
                if identities != {(r['pid'], r['created']) for r in old['targets']}:
                    raise RuntimeError('paused_instance_identity_changed')
                return {'phase': 'paused', 'count': len(old['targets']), 'already_paused': True}
            raise RuntimeError('pause_transition_requires_review')
    native = native or Native()
    root, rows = select(scan(profile), profile, proxy_server)
    targets = [{k: row[k] for k in ('pid', 'created', 'parent')} for row in sorted(rows, key=lambda r: r['pid'] != root)]
    handles = []
    journal = {'phase': 'pausing', 'profile': str(profile), 'targets': targets}
    try:
        for row in targets:
            handles.append((row, native.open(row)))
            row['step'] = 'not_started'
        save(journal_path, journal)
        for row, handle in handles:
            row['step'] = 'pause_pending'; save(journal_path, journal)
            native.pause(handle)
            row['step'] = 'paused'; save(journal_path, journal)
        _, current = select(scan(profile), profile, proxy_server)
        if {r['pid'] for r in current} != {r['pid'] for r in targets}:
            raise RuntimeError('process_tree_changed')
        journal['phase'] = 'paused'; save(journal_path, journal)
        return {'phase': 'paused', 'count': len(targets)}
    finally:
        # Intentionally no automatic resume: failure protection survives caller exit.
        for _, handle in handles:
            native.close(handle)


def resume(journal_path, native=None, scan=inventory):
    if not journal_path.exists():
        return {'phase': 'resumed', 'count': 0}
    journal = json.loads(journal_path.read_text(encoding='utf-8'))
    if journal['phase'] == 'resumed':
        return {'phase': 'resumed', 'count': 0, 'already_resumed': True}
    if any(r['step'] in ('pause_pending', 'resume_pending') for r in journal['targets']):
        raise RuntimeError('ambiguous_native_transition_requires_review')
    native = native or Native()
    rows = {r['pid']: r for r in scan(journal['profile'])}
    handles = []
    try:
        for row in reversed(journal['targets']):
            if row['step'] != 'paused':
                continue
            current = rows.get(row['pid'])
            if not current or abs(current['created'] - row['created']) >= 10:
                row['step'] = 'exited'
                continue
            handles.append((row, native.open(row)))
        journal['phase'] = 'resuming'; save(journal_path, journal)
        for row, handle in handles:
            row['step'] = 'resume_pending'; save(journal_path, journal)
            native.resume(handle)
            row['step'] = 'resumed'; save(journal_path, journal)
        journal['phase'] = 'resumed'; save(journal_path, journal)
        return {'phase': 'resumed', 'count': len(handles)}
    finally:
        for _, handle in handles:
            native.close(handle)
