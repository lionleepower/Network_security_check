"""Local guard service and on-demand refresh; no Codex, login or Claude launch.

run owns an OS lock; ensure requests and waits for one real capture. All files are
private. Uses the same decision engine and single-switch budget as the old guard.
"""
import argparse
import ctypes
import json
import os
from pathlib import Path
import queue
import re
import subprocess
import sys
import threading
import time
import uuid
from guard_store import save,lock
from ippure_guard import Guard


def read(path):
    return json.loads(Path(path).read_text(encoding='utf-8'))


def in_job():
    if os.name!='nt':return False
    from ctypes import wintypes
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.GetCurrentProcess.restype=wintypes.HANDLE
    kernel.IsProcessInJob.argtypes=[wintypes.HANDLE,wintypes.HANDLE,ctypes.POINTER(wintypes.BOOL)]
    value=wintypes.BOOL()
    if not kernel.IsProcessInJob(kernel.GetCurrentProcess(),None,ctypes.byref(value)):raise OSError('process_job_query_failed')
    return bool(value.value)


def allowed(state):
    return state.get('enabled') is True and state.get('phase') in ('watching','recovered')


def make_guard(directory):
    if read(directory/'config.json').get('schema_version')==2:
        from portable_guard import PortableGuard
        return PortableGuard(directory)
    return Guard(directory)


def capture(directory,config):
    command=[config['node'],str(Path(__file__).with_name('native_ippure_collector.cjs')),str(directory)]
    child=subprocess.Popen(command,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,text=True,encoding='utf-8',creationflags=getattr(subprocess,'CREATE_NO_WINDOW',0))
    results=queue.Queue()
    threading.Thread(target=lambda:results.put(child.stdout.readline()),daemon=True).start()
    try:
        line=results.get(timeout=85)
        result=json.loads(line)
        if not result.get('ok'):raise RuntimeError(result.get('error','page_collection_failed'))
        return child,result['raw']
    except BaseException:
        child.stdin.close()
        try:child.wait(timeout=12)
        except subprocess.TimeoutExpired:child.terminate()
        raise


def cycle(directory,config):
    with lock(directory/'guard.lock'):
        guard=make_guard(directory);guard.recover()
        if not allowed(guard.state):return {'ok':False,'reason':'guard_disabled_or_latched'}
    child=None
    try:
        child,raw=capture(directory,config)
        save(directory/'native-live.json',raw)
        with lock(directory/'guard.lock'):
            guard=make_guard(directory);result=guard.ingest(raw)
            if result.get('action')=='repeat_ippure_test':
                # Release this browser; a second actual page is captured immediately.
                child.stdin.write('close\n');child.stdin.flush();child.stdin.close();child.wait(timeout=15);child=None
                child,raw=capture(directory,config);save(directory/'native-live.json',raw)
                result=guard.ingest(raw)
            valid=result.get('last_observed_at')==raw['observed_at']
            return {'ok':valid and allowed(guard.state),'guard':result,'reason':None if valid else 'detector_channel_unverified'}
    except Exception:
        with lock(directory/'guard.lock'):
            guard=make_guard(directory)
            if guard.state.get('phase') in ('switch_required','rechecking'):
                result=guard.halt('native_retest_collection_failed')
                return {'ok':False,'reason':'native_retest_collection_failed','guard':result}
        raise
    finally:
        if child:
            child.stdin.close()
            try:child.wait(timeout=15)
            except subprocess.TimeoutExpired:
                # Do not terminate a possibly suspended browser or alter pause counts.
                pass


def run(directory):
    config=read(directory/'native-config.json')
    with lock(directory/'native-worker.lock'):
        due=0;last_request=None;run_id=str(uuid.uuid4())
        while True:
            if (directory/'native-stop.json').exists() and read(directory/'native-stop.json').get('run_id')==run_id:
                save(directory/'native-status.json',{'pid':os.getpid(),'run_id':run_id,'ok':False,'stopped':True,'checked_at':time.time()});return
            now=time.time();request=read(directory/'native-request.json') if (directory/'native-request.json').exists() else {}
            request_id=request.get('id');requested=request_id and request_id!=last_request
            if now>=due or requested:
                try:result=cycle(directory,config)
                except Exception as error:
                    code=str(error)
                    result={'ok':False,'reason':code if re.fullmatch('[a-z_]{1,80}',code) else 'native_capture_failed'}
                save(directory/'native-status.json',{'pid':os.getpid(),'run_id':run_id,'job_associated':in_job(),'checked_at':time.time(),'request_id':request_id,**result})
                last_request=request_id;due=time.time()+config.get('interval_seconds',300)
            time.sleep(0.5)


def ensure(directory,timeout=100):
    # Request first, then try launching. OS lock prevents duplicate long-lived workers.
    request_id=str(uuid.uuid4());save(directory/'native-request.json',{'id':request_id,'requested_at':time.time()})
    flags=getattr(subprocess,'CREATE_NO_WINDOW',0)|getattr(subprocess,'DETACHED_PROCESS',0)
    if in_job():flags|=getattr(subprocess,'CREATE_BREAKAWAY_FROM_JOB',0)
    with (directory/'native-worker.log').open('ab') as log:
        subprocess.Popen([sys.executable,'-X','utf8',str(Path(__file__).resolve()),'run','--directory',str(directory)],stdin=subprocess.DEVNULL,stdout=log,stderr=log,cwd=directory,creationflags=flags,close_fds=True)
    deadline=time.time()+timeout
    while time.time()<deadline:
        try:status=read(directory/'native-status.json')
        except (OSError,ValueError):status={}
        if status.get('request_id')==request_id:return status
        time.sleep(0.5)
    return {'ok':False,'reason':'automatic_capture_timeout'}


def main():
    p=argparse.ArgumentParser();p.add_argument('command',choices=['run','ensure','status','stop']);p.add_argument('--directory',required=True,type=Path);a=p.parse_args();d=a.directory.resolve(strict=True)
    if a.command=='run':
        try:run(d)
        except (OSError,RuntimeError):return 0  # Another worker already owns the lock.
        return 0
    if a.command=='stop':
        status=read(d/'native-status.json')
        if not status.get('run_id'):raise ValueError('worker_restart_required_before_graceful_stop')
        save(d/'native-stop.json',{'run_id':status['run_id']});result={'ok':True,'stop_requested':True,'does_not_resume_browser':True}
    else:result=ensure(d) if a.command=='ensure' else read(d/'native-status.json')
    print(json.dumps(result,ensure_ascii=False));return 0 if result.get('ok') else 1


if __name__=='__main__':
    try:raise SystemExit(main())
    except Exception:
        print(json.dumps({'ok':False,'reason':'native_service_unavailable'}));raise SystemExit(1)
