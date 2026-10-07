"""Fixed public synthetic tests inside a zero-capability AppContainer only."""
import ctypes
from ctypes import wintypes
import hashlib
import json
import os
from pathlib import Path
import sys
import time
sys.path.insert(0,str(Path(__file__).absolute().parent))
from security_policy import (ROOT, SecurityError, require_mode, result_path,
    configure_offline, public_fixture, checked_path, install_audit_guard)

class JobLimits(ctypes.Structure):
    _fields_=[('process_time',ctypes.c_longlong),('job_time',ctypes.c_longlong),('flags',wintypes.DWORD),('min_working',ctypes.c_size_t),('max_working',ctypes.c_size_t),('active',wintypes.DWORD),('affinity',ctypes.c_size_t),('priority',wintypes.DWORD),('scheduling',wintypes.DWORD)]
class ExtendedLimits(ctypes.Structure):
    _fields_=[('basic',JobLimits),('io',ctypes.c_ulonglong*6),('process_memory',ctypes.c_size_t),('job_memory',ctypes.c_size_t),('peak_process',ctypes.c_size_t),('peak_job',ctypes.c_size_t)]

def container_check():
    if os.name!='nt': raise SecurityError('WINDOWS_REQUIRED')
    adv=ctypes.WinDLL('advapi32',use_last_error=True)
    kernel=ctypes.WinDLL('kernel32',use_last_error=True)
    kernel.GetCurrentProcess.restype=wintypes.HANDLE
    kernel.CloseHandle.argtypes=[wintypes.HANDLE]
    kernel.LocalFree.argtypes=[ctypes.c_void_p]
    adv.OpenProcessToken.argtypes=[wintypes.HANDLE,wintypes.DWORD,ctypes.POINTER(wintypes.HANDLE)]
    adv.GetTokenInformation.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD)]
    adv.ConvertSidToStringSidW.argtypes=[ctypes.c_void_p,ctypes.POINTER(wintypes.LPWSTR)]
    token=wintypes.HANDLE()
    if not adv.OpenProcessToken(kernel.GetCurrentProcess(),8,ctypes.byref(token)):raise SecurityError('TOKEN_CHECK_FAILED')
    try:
        yes,size=wintypes.DWORD(),wintypes.DWORD()
        if not adv.GetTokenInformation(token,29,ctypes.byref(yes),4,ctypes.byref(size)) or yes.value!=1:
            raise SecurityError('APPCONTAINER_REQUIRED')
        adv.GetTokenInformation(token,30,None,0,ctypes.byref(size))
        if not 4<=size.value<=65536:raise SecurityError('CAPABILITIES_SIZE_INVALID')
        buf=ctypes.create_string_buffer(size.value)
        if not adv.GetTokenInformation(token,30,buf,size.value,ctypes.byref(size)):raise SecurityError('CAPABILITIES_CHECK_FAILED')
        if ctypes.cast(buf,ctypes.POINTER(wintypes.DWORD))[0]!=0:raise SecurityError('ZERO_CAPABILITIES_REQUIRED')
        adv.GetTokenInformation(token,31,None,0,ctypes.byref(size))
        if not ctypes.sizeof(ctypes.c_void_p)<=size.value<=65536:raise SecurityError('APPCONTAINER_SID_SIZE_INVALID')
        info=ctypes.create_string_buffer(size.value);text=wintypes.LPWSTR()
        if not adv.GetTokenInformation(token,31,info,size.value,ctypes.byref(size)):raise SecurityError('APPCONTAINER_SID_CHECK_FAILED')
        sid=ctypes.cast(info,ctypes.POINTER(ctypes.c_void_p))[0]
        if not adv.ConvertSidToStringSidW(sid,ctypes.byref(text)):raise SecurityError('APPCONTAINER_SID_CHECK_FAILED')
        try:
            if not os.environ.get('LAYA_EXPECTED_SID') or text.value!=os.environ['LAYA_EXPECTED_SID']:raise SecurityError('APPCONTAINER_SID_MISMATCH')
        finally:kernel.LocalFree(text)
    finally:kernel.CloseHandle(token)
    kernel.QueryInformationJobObject.argtypes=[wintypes.HANDLE,ctypes.c_int,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(wintypes.DWORD)]
    limits=ExtendedLimits();size=wintypes.DWORD()
    if not kernel.QueryInformationJobObject(None,9,ctypes.byref(limits),ctypes.sizeof(limits),ctypes.byref(size)):
        raise SecurityError('ISOLATION_JOB_REQUIRED')
    if limits.basic.active!=1 or limits.basic.flags & 0x2008 != 0x2008:
        raise SecurityError('ISOLATION_JOB_LIMITS_REQUIRED')
    return {'appcontainer':True,'network_capabilities':0,'expected_sid_match':True,'job_active_process_limit':1,'job_kill_on_close':True}

def probe():
    # Keep the previous explicit-denial assertion. Do NOT reinterpret send success.
    import socket
    rows=[]
    for family,kind,address in [(socket.AF_INET,socket.SOCK_STREAM,('1.1.1.1',443)),
                               (socket.AF_INET,socket.SOCK_DGRAM,('1.1.1.1',53)),
                               (socket.AF_INET,socket.SOCK_STREAM,('127.0.0.1',80)),
                               (socket.AF_INET6,socket.SOCK_STREAM,('2606:4700:4700::1111',443))]:
        s=socket.socket(family,kind);s.settimeout(3)
        try:
            s.connect(address)
            if kind==socket.SOCK_DGRAM:s.send(b'LAYA_SYNTHETIC_NETWORK_PROBE')
            code=0
        except OSError as e:code=e.winerror or e.errno
        finally:s.close()
        rows.append({'family':family,'kind':kind,'address':address[0],'error':code,'denied':code==10013})
    return {'status':'PASS' if all(r['denied'] for r in rows) else 'FAIL','scope':'original explicit API-denial check only; not whole-boundary acceptance','probes':rows,'whole_boundary_egress':'NOT_RUN','business_input_enabled':False}

def evaluate(attempts):
    # Pin the entire public fixture before any ML import or tokenization.
    fixture_bytes=public_fixture()
    fixture=json.loads(fixture_bytes)
    model_path=checked_path(ROOT,'models/laya-multilingual-prepared',True)
    manifest=json.loads(checked_path(ROOT,'prepared-model-manifest.json',True).read_text(encoding='utf-8'))
    for row in manifest['files']:
        with checked_path(model_path,row['path'],True).open('rb') as src:
            if hashlib.file_digest(src,'sha256').hexdigest()!=row['sha256']:raise SecurityError('MODEL_HASH_MISMATCH')
    started=time.perf_counter()
    import torch
    from laya import load
    torch.set_num_threads(4)
    # This existing absolute local directory is the only model identifier.
    model=load(str(model_path),device='cpu',compile=False,fast=False)
    load_seconds=time.perf_counter()-started
    rows=[]
    for case in fixture['cases']:
        start=time.perf_counter();answer=model.predict(case['state'],fixture['questions'])
        field=answer['answers']['department'];choice=field['choice']
        rows.append({'id':case['id'],'expected':case['expected'],'choice':choice,'correct':choice==case['expected'],
                     'answer_confidence':field.get('answer_confidence'),'confidence':field.get('confidence'),
                     'seconds':time.perf_counter()-start,'state_tokens':len(model.tok.encode(case['state'],add_special_tokens=False))})
    return {'status':'PASS','meaning':'execution completed; no security or quality approval','device':str(model.device),
            'torch_version':torch.__version__,'cuda_available':torch.cuda.is_available(),
            'fixture_sha256':hashlib.sha256(fixture_bytes).hexdigest(),'load_seconds':load_seconds,
            'attempts':len(rows),'correct':sum(x['correct'] for x in rows),'retry_count':0,
            'python_network_or_subprocess_attempts':attempts,'business_input_enabled':False,'rows':rows}

def guard_check():
    import socket
    import subprocess
    from native_probe import child_creation_check
    rows=[]
    try:socket.getaddrinfo('example.com',443)
    except SecurityError as e:rows.append({'test':'python_dns_audit','status':'PASS' if str(e)=='NETWORK_DENIED' else 'FAIL'})
    else:rows.append({'test':'python_dns_audit','status':'FAIL'})
    try:subprocess.run([sys.executable,'-I','-S','-B','-c','pass'],check=True)
    except SecurityError as e:rows.append({'test':'python_subprocess_audit','status':'PASS' if str(e)=='SUBPROCESS_DENIED' else 'FAIL'})
    else:rows.append({'test':'python_subprocess_audit','status':'FAIL'})
    rows.append(dict(test='native_child_creation',**child_creation_check()))
    target=checked_path(ROOT,'scripts/denied-synthetic-write-'+str(os.getpid())+'.txt')
    try:
        with target.open('x',encoding='utf-8') as f:f.write('PUBLIC_SYNTHETIC_ONLY')
    except PermissionError:rows.append({'test':'appcontainer_code_write','status':'PASS'})
    else:rows.append({'test':'appcontainer_code_write','status':'FAIL','reason':'Unexpected file retained'})
    try:(ROOT/'build/public-canary.txt').read_bytes()
    except PermissionError:rows.append({'test':'ungranted_public_canary_read','status':'PASS'})
    except FileNotFoundError:rows.append({'test':'ungranted_public_canary_read','status':'NOT_RUN','reason':'Host control canary missing'})
    else:rows.append({'test':'ungranted_public_canary_read','status':'FAIL'})
    rows.append({'test':'site_import_disabled','status':'PASS' if 'site' not in sys.modules else 'FAIL'})
    return {'status':'PASS' if all(r['status']=='PASS' for r in rows) else 'FAIL','tests':rows,'business_input_enabled':False}

def main():
    output=None
    try:
        if len(sys.argv)!=3:raise SecurityError('BUSINESS_INPUT_DISABLED; fixed synthetic mode and output anchor required')
        mode=sys.argv[1];require_mode(mode)
        output=result_path(sys.argv[2])
        boundary=container_check()
        if not sys.flags.no_site or 'site' in sys.modules:raise SecurityError('EARLY_SITE_IMPORT_DENIED')
        configure_offline()
        if mode=='probe':result=probe()
        else:
            attempts=install_audit_guard() # Installed BEFORE torch, laya, or native probe imports.
            if mode=='evaluate':result=evaluate(attempts)
            elif mode=='guard-check':result=guard_check()
            else:
                from native_probe import run
                result=run('container')
        result['boundary']=boundary
        with output.open('x',encoding='utf-8') as f:json.dump(result,f,ensure_ascii=False,indent=2)
        return 0 if result['status']=='PASS' else 1
    except Exception as e:
        code=str(e) if isinstance(e,SecurityError) else 'LOCAL_EXECUTION_ERROR'
        if output is not None and not output.exists():
            with output.open('x',encoding='utf-8') as f:json.dump({'status':'FAIL','error_type':type(e).__name__,'error_code':code,'business_input_enabled':False},f)
        print(code,file=sys.stderr)
        return 1
if __name__=='__main__':raise SystemExit(main())