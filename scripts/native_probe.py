"""Fixed public-synthetic WinSock probes, bypassing Python socket audit hooks.

No user payload, arbitrary destination, shell, credentials, or model is accepted.
A send return code alone is NOT receiver or packet evidence.
"""
import ctypes as c
from ctypes import wintypes as w
import json
import os
from pathlib import Path
import struct
import sys
import time

class V4(c.Structure):
    _fields_=[('family',c.c_ushort),('port',c.c_ushort),('addr',c.c_ubyte*4),('zero',c.c_ubyte*8)]
class V6(c.Structure):
    _fields_=[('family',c.c_ushort),('port',c.c_ushort),('flow',c.c_uint32),('addr',c.c_ubyte*16),('scope',c.c_uint32)]
class Poll(c.Structure):
    _fields_=[('fd',c.c_size_t),('events',c.c_short),('revents',c.c_short)]

PORTS={'tcp4':39471,'udp4':39472,'tcp6':39473,'udp6':39474}

def winsock():
    ws=c.WinDLL('ws2_32',use_last_error=True)
    ws.WSAStartup.argtypes=[c.c_ushort,c.c_void_p]
    ws.socket.argtypes=[c.c_int,c.c_int,c.c_int];ws.socket.restype=c.c_size_t
    ws.connect.argtypes=[c.c_size_t,c.c_void_p,c.c_int]
    ws.sendto.argtypes=[c.c_size_t,c.c_void_p,c.c_int,c.c_int,c.c_void_p,c.c_int]
    ws.send.argtypes=[c.c_size_t,c.c_void_p,c.c_int,c.c_int]
    ws.recv.argtypes=[c.c_size_t,c.c_void_p,c.c_int,c.c_int]
    ws.closesocket.argtypes=[c.c_size_t]
    ws.ioctlsocket.argtypes=[c.c_size_t,c.c_long,c.POINTER(c.c_ulong)]
    ws.WSAPoll.argtypes=[c.POINTER(Poll),c.c_ulong,c.c_int]
    ws.getsockopt.argtypes=[c.c_size_t,c.c_int,c.c_int,c.c_void_p,c.POINTER(c.c_int)]
    ws.InetPtonW.argtypes=[c.c_int,w.LPCWSTR,c.c_void_p]
    ws.GetAddrInfoW.argtypes=[w.LPCWSTR,w.LPCWSTR,c.c_void_p,c.POINTER(c.c_void_p)]
    ws.FreeAddrInfoW.argtypes=[c.c_void_p]
    data=c.create_string_buffer(512)
    rc=ws.WSAStartup(0x202,data)
    if rc: raise RuntimeError('WSA_STARTUP_FAILED_'+str(rc))
    return ws

def dns_query():
    name=b''.join(bytes([len(p)])+p for p in (b'laya-public-synthetic',b'invalid'))+b'\0'
    return struct.pack('!HHHHHH',0x4c41,0x0100,1,0,0,0)+name+struct.pack('!HH',1,1)

def attempt(ws, family, kind, address, port, label, scope):
    row={'family':family,'transport':'TCP' if kind==1 else 'UDP','target':address,'port':port,'scope':scope,'api':'native_ws2_32','send_return':None,'received_bytes':0,'error':None}
    s=ws.socket(family,kind,0)
    if s==c.c_size_t(-1).value:
        row['error']=ws.WSAGetLastError();return row
    try:
        one=c.c_ulong(1)
        if ws.ioctlsocket(s,c.c_long(0x8004667e),c.byref(one)):
            row['error']=ws.WSAGetLastError();return row
        dest=V4() if family==2 else V6();dest.family=family;dest.port=int.from_bytes(port.to_bytes(2,'big'),'little')
        if ws.InetPtonW(family,address,dest.addr)!=1: raise RuntimeError('INVALID_FIXED_DESTINATION')
        marker=('LAYA_PUBLIC_'+label.upper()).encode('ascii')
        payload=marker if scope=='loopback' else dns_query()
        if kind==1:
            rc=ws.connect(s,c.byref(dest),c.sizeof(dest))
            error=ws.WSAGetLastError() if rc else 0
            if error==10035:
                poll=Poll(s,0x10,0)
                ready=ws.WSAPoll(c.byref(poll),1,2000)
                if ready>0:
                    code=c.c_int();size=c.c_int(4)
                    if ws.getsockopt(s,0xffff,0x1007,c.byref(code),c.byref(size)):
                        error=ws.WSAGetLastError()
                    else:error=code.value
                else:error=10060 if ready==0 else ws.WSAGetLastError()
            row['error']=error
            if error==0 and scope=='loopback':
                row['send_return']=ws.send(s,payload,len(payload),0)
                if row['send_return']==-1:row['error']=ws.WSAGetLastError()
        else:
            row['send_return']=ws.sendto(s,payload,len(payload),0,c.byref(dest),c.sizeof(dest))
            row['error']=ws.WSAGetLastError() if row['send_return']==-1 else 0
            if row['error']==0 and scope=='public':
                poll=Poll(s,0x100,0)
                if ws.WSAPoll(c.byref(poll),1,1500)>0:
                    data=c.create_string_buffer(512);got=ws.recv(s,data,512,0)
                    if got>0:
                        row['received_bytes']=got
                        row['dns_response_matches_query']=got>=12 and data.raw[:2]==b'LA' and bool(data.raw[2]&0x80)
                    elif got==-1:row['receive_error']=ws.WSAGetLastError()
        row['explicit_access_denied']=row['error']==10013
        row['interpretation']='EXPLICIT_API_DENIAL' if row['explicit_access_denied'] else 'OBSERVATION_ONLY_NOT_EGRESS_ACCEPTANCE'
        return row
    finally:ws.closesocket(s)

def run(label):
    if label not in ('control','container'): raise ValueError('FIXED_SYNTHETIC_LABEL_REQUIRED')
    ws=winsock()
    try:
        rows=[]
        for fam,host,suffix in ((2,'127.0.0.1','4'),(23,'::1','6')):
            for kind,protocol in ((1,'tcp'),(2,'udp')):
                rows.append(attempt(ws,fam,kind,host,PORTS[protocol+suffix],label,'loopback'))
        for fam,host in ((2,'1.1.1.1'),(23,'2606:4700:4700::1111')):
            rows.append(attempt(ws,fam,1,host,443,label,'public'))
            rows.append(attempt(ws,fam,2,host,53,label,'public'))
        dns=[]
        for name in ('example.com','laya-public-synthetic.invalid'):
            result=c.c_void_p()
            code=ws.GetAddrInfoW(name,None,None,c.byref(result))
            dns.append({'name':name,'api':'native_GetAddrInfoW','return_code':code,'result_present':bool(result),'interpretation':'DNS_BROKER_AND_CACHE_PATH_NOT_ATTESTED'})
            if result:ws.FreeAddrInfoW(result)
        return {'status':'HOLD','execution_completed':True,'label':label,'probes':rows,'dns':dns,
                'external_packet_capture':'NOT_RUN','whole_boundary_egress':'NOT_RUN','business_input_enabled':False}
    finally:ws.WSACleanup()

class SI(c.Structure):
    _fields_=[('cb',w.DWORD),('reserved',w.LPWSTR),('desktop',w.LPWSTR),('title',w.LPWSTR),('x',w.DWORD),('y',w.DWORD),('xs',w.DWORD),('ys',w.DWORD),('xc',w.DWORD),('yc',w.DWORD),('fill',w.DWORD),('flags',w.DWORD),('show',w.WORD),('reserved2',w.WORD),('reserved3',c.c_void_p),('input',w.HANDLE),('output',w.HANDLE),('error',w.HANDLE)]
class PI(c.Structure):
    _fields_=[('process',w.HANDLE),('thread',w.HANDLE),('pid',w.DWORD),('tid',w.DWORD)]

def child_creation_check():
    # Only this process's fixed interpreter and a no-op public script are attempted.
    kernel=c.WinDLL('kernel32',use_last_error=True)
    kernel.CreateProcessW.argtypes=[w.LPCWSTR,w.LPWSTR,c.c_void_p,c.c_void_p,w.BOOL,w.DWORD,c.c_void_p,w.LPCWSTR,c.POINTER(SI),c.POINTER(PI)]
    kernel.CloseHandle.argtypes=[w.HANDLE]
    kernel.TerminateProcess.argtypes=[w.HANDLE,w.UINT]
    kernel.WaitForSingleObject.argtypes=[w.HANDLE,w.DWORD]
    si=SI();si.cb=c.sizeof(si);pi=PI()
    cmd=c.create_unicode_buffer('"'+sys.executable+'" -I -S -B -c "pass"')
    success=kernel.CreateProcessW(sys.executable,cmd,None,None,False,0x08000000,None,None,c.byref(si),c.byref(pi))
    code=c.get_last_error() if not success else 0
    if success:
        kernel.TerminateProcess(pi.process,124);kernel.WaitForSingleObject(pi.process,5000)
        kernel.CloseHandle(pi.thread);kernel.CloseHandle(pi.process)
    return {'created':bool(success),'winerror':code,'status':'PASS' if not success else 'FAIL','scope':'native child creation denied; token/job assertions are separate'}

if __name__=='__main__':
    sys.stdout.reconfigure(encoding='utf-8')
    if sys.argv[1:]!=['--control']: raise SystemExit('Only --control is supported directly')
    print(json.dumps(run('control'),indent=2))