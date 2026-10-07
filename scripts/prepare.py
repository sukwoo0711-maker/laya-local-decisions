"""Public downloads are explicit; install, verify and seal never download.

Run with an approved Python 3.12 x64 interpreter. Preserve existing artifacts.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import shutil
import sys
import urllib.parse
import urllib.request
import uuid
import zipfile
sys.path.insert(0, str(Path(__file__).absolute().parent))
from security_policy import checked_path, public_fixture
ROOT = Path(os.path.abspath(Path(__file__).parent.parent))
PYTHON = {'url':'https://www.python.org/ftp/python/3.12.10/python-3.12.10-embed-amd64.zip',
          'sha256':'4acbed6dd1c744b0376e3b1cf57ce906f9dc9e95e68824584c8099a63025a3c3',
          'file':'python-3.12.10-embed-amd64.zip'}
HOSTS = frozenset(('www.python.org','files.pythonhosted.org','huggingface.co',
                  'cdn-lfs.huggingface.co','cdn-lfs.hf.co','cdn-lfs-us-1.hf.co',
                  'cdn-lfs-eu-1.hf.co','cas-bridge.xethub.hf.co'))
PTH = 'python312.zip\n.\nLib/site-packages\n'

def digest(path):
    with path.open('rb') as f: return hashlib.file_digest(f,'sha256').hexdigest()

def read(name):
    return json.loads(checked_path(ROOT,name,True).read_text(encoding='utf-8-sig'))

def validate_url(url):
    u=urllib.parse.urlsplit(url)
    if u.scheme!='https' or u.hostname not in HOSTS or u.username is not None or u.password is not None or u.port not in (None,443) or u.fragment:
        raise ValueError('PUBLIC_HTTPS_ARTIFACT_URL_REQUIRED')
    return url

class PublicRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        validate_url(newurl)
        return super().redirect_request(req,fp,code,msg,headers,newurl)

def assets():
    yield checked_path(ROOT/'artifacts',PYTHON['file']),PYTHON
    for row in read('dependency-lock.json'):
        yield checked_path(ROOT/'artifacts/wheels-v2',row['file']),row
    for row in read('model-manifest.json')['files']:
        yield checked_path(ROOT/'models/laya-multilingual',row['path']),row

def verify_assets():
    count=0
    for path,row in assets():
        if digest(path)!=row['sha256']: raise ValueError('ARTIFACT_HASH_MISMATCH: '+path.name)
        count+=1
    return count

def download():
    # No environment proxies, credentials, unpinned hosts, or inference fallback.
    opener=urllib.request.build_opener(urllib.request.ProxyHandler({}), PublicRedirect())
    for path,row in assets():
        if path.exists():
            if digest(path)!=row['sha256']: raise ValueError('EXISTING_ARTIFACT_MISMATCH_PRESERVED')
            continue
        validate_url(row['url'])
        path.parent.mkdir(parents=True,exist_ok=True)
        checked_path(ROOT,str(path.relative_to(ROOT)))
        with opener.open(row['url'],timeout=120) as response, path.open('xb') as out:
            validate_url(response.url)
            shutil.copyfileobj(response,out)
        if digest(path)!=row['sha256']: raise ValueError('DOWNLOAD_HASH_MISMATCH_PRESERVED')
    print(json.dumps({'status':'PASS','verified_artifacts':verify_assets(),'business_input_enabled':False}))

def archive_rows(archive,wheel=False):
    with zipfile.ZipFile(archive) as z:
        for entry in z.infolist():
            if entry.is_dir(): continue
            if (entry.external_attr >> 16) & 0o170000 == 0o120000:
                raise ValueError('ARCHIVE_SYMLINK_DENIED')
            name=entry.filename
            parts=name.split('/')
            if wheel and parts[0].endswith('.data'):
                if len(parts)<3: raise ValueError('INVALID_WHEEL_PATH')
                if parts[1] not in ('purelib','platlib'): continue
                name='/'.join(parts[2:])
            checked_path(ROOT,name)
            yield name,z.read(entry)

def extract(archive,target,wheel=False):
    for name,data in archive_rows(archive,wheel):
        dest=checked_path(target,name)
        dest.parent.mkdir(parents=True,exist_ok=True)
        with dest.open('xb') as out: out.write(data)

def install():
    count=verify_assets()
    runtime=checked_path(ROOT,'runtime-v2')
    prepared=checked_path(ROOT,'models/laya-multilingual-prepared')
    if runtime.exists() or prepared.exists(): raise ValueError('INSTALLATION_EXISTS_PRESERVED; use verify')
    runtime.mkdir()
    extract(ROOT/'artifacts'/PYTHON['file'],runtime)
    for row in read('dependency-lock.json'):
        extract(ROOT/'artifacts/wheels-v2'/row['file'],runtime/'Lib/site-packages',True)
    (runtime/'python312._pth').write_text(PTH,encoding='utf-8')
    upstream={r['path']:r for r in read('model-manifest.json')['files']}
    for row in read('prepared-model-manifest.json')['files']:
        src=checked_path(ROOT/'models/laya-multilingual',row['path'],True)
        dst=checked_path(prepared,row['path'])
        dst.parent.mkdir(parents=True,exist_ok=True)
        if row['path']=='tokenizer/tokenizer_config.json':
            cfg=json.loads(src.read_text(encoding='utf-8'))
            extra=cfg['extra_special_tokens']
            if not isinstance(extra,list): raise ValueError('UNEXPECTED_TOKENIZER_CONFIGURATION')
            cfg['extra_special_tokens']={f'extra_{i}':v for i,v in enumerate(extra)}
            with dst.open('x',encoding='utf-8') as f: f.write(json.dumps(cfg,ensure_ascii=False,indent=2)+'\n')
        else:
            with src.open('rb') as inp,dst.open('xb') as out: shutil.copyfileobj(inp,out)
        if digest(dst)!=row['sha256'] or row['original_sha256']!=upstream[row['path']]['sha256']:
            raise ValueError('PREPARED_MODEL_HASH_MISMATCH')
    print(json.dumps({'status':'PASS','verified_artifacts':count,'business_input_enabled':False}))

def files_in(base):
    # Validate each directory before traversing it; never follow a junction.
    pending=[base]
    while pending:
        folder=pending.pop()
        for child in folder.iterdir():
            checked_path(ROOT,str(child.relative_to(ROOT)),True)
            if child.is_dir(): pending.append(child)
            else: yield child

def verify():
    count=verify_assets()
    expected={}
    for name,data in archive_rows(ROOT/'artifacts'/PYTHON['file']):
        if name!='python312._pth': expected['runtime-v2/'+name]=hashlib.sha256(data).hexdigest()
    # Existing text-mode installation uses platform newlines; validate text exactly.
    pth=checked_path(ROOT,'runtime-v2/python312._pth',True)
    if pth.read_text(encoding='utf-8')!=PTH: raise ValueError('UNEXPECTED_PYTHON_SEARCH_PATH')
    expected['runtime-v2/python312._pth']=digest(pth)
    checked=0
    for row in read('dependency-lock.json'):
        for name,data in archive_rows(ROOT/'artifacts/wheels-v2'/row['file'],True):
            key='runtime-v2/Lib/site-packages/'+name
            value=hashlib.sha256(data).hexdigest()
            if key in expected and expected[key]!=value: raise ValueError('CONFLICTING_WHEEL_FILES')
            expected[key]=value
            checked+=1
    for row in read('prepared-model-manifest.json')['files']:
        expected['models/laya-multilingual-prepared/'+row['path']]=row['sha256']
    for relative,value in expected.items():
        if digest(checked_path(ROOT,relative,True))!=value: raise ValueError('INSTALLED_HASH_MISMATCH: '+relative)
    actual={p.relative_to(ROOT).as_posix() for d in ('runtime-v2','models/laya-multilingual-prepared') for p in files_in(checked_path(ROOT,d,True))}
    if actual != set(expected):
        raise ValueError('UNEXPECTED_OR_MISSING_INSTALLED_FILES: '+str(len(actual.symmetric_difference(expected))))
    public_fixture()
    print(json.dumps({'status':'PASS','verified_artifacts':count,'installed_dependency_files':checked,'exact_installed_files':len(expected),'business_input_enabled':False}))
    return expected

def seal():
    expected=verify()
    for file in files_in(checked_path(ROOT,'scripts',True)):
        expected[file.relative_to(ROOT).as_posix()]=digest(file)
    for name in ('tests/synthetic-ko.json','model-manifest.json','prepared-model-manifest.json','dependency-lock.json','build/LayaLauncher.exe'):
        expected[name]=digest(checked_path(ROOT,name,True))
    data=('LAYA_OFFLINE_INTEGRITY_V1\n'+''.join(v+'\t'+k+'\n' for k,v in sorted(expected.items()))).encode('utf-8')
    target=checked_path(ROOT,'build/offline-integrity.tsv')
    if target.exists() and target.read_bytes()!=data:
        prior=target.with_name('offline-integrity.prior-'+uuid.uuid4().hex+'.tsv')
        with prior.open('xb') as out: out.write(target.read_bytes())
    target.write_bytes(data)
    print(json.dumps({'status':'PASS','sealed_files':len(expected),'seal_sha256':hashlib.sha256(data).hexdigest(),'business_input_enabled':False,'meaning':'local change detection, not a signed supply-chain attestation'}))

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('operation',choices=['download','install','verify','seal'])
    a=p.parse_args()
    if sys.version_info[:2]!=(3,12): raise RuntimeError('APPROVED_PYTHON_3_12_REQUIRED')
    {'download':download,'install':install,'verify':verify,'seal':seal}[a.operation]()
if __name__=='__main__': main()