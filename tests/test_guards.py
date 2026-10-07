"""Actual launcher/worker negative tests; public synthetic fixtures only."""
from pathlib import Path
import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import uuid
ROOT=Path(os.path.abspath(Path(__file__).parent.parent))
launcher=ROOT/'build/LayaLauncher.exe'
rows=[]
def call(label,args,expected=1,contains=None):
    cmd=[str(x) for x in args]
    r=subprocess.run(cmd,cwd=ROOT,capture_output=True,text=True,encoding='utf-8',errors='replace',timeout=120)
    row={'test':label,'command':cmd,'cwd':str(ROOT),'exit_code':r.returncode,'stdout':r.stdout,'stderr':r.stderr,'expected_exit':expected,'assertion':contains,'status':'PASS' if r.returncode==expected and (contains is None or contains in r.stderr) else 'FAIL'}
    rows.append(row)
    return r

def main(evidence):
    tag='guards-'+uuid.uuid4().hex
    call('production_input_disabled',[launcher,'predict',ROOT/'private'/(tag+'.json')],contains='Production input is disabled')
    call('output_path_boundary',[launcher,'evaluate',ROOT/(tag+'.json')],contains='Request must be inside private directory')
    direct=ROOT/'private'/(tag+'-direct.json')
    call('direct_model_execution_refused',[ROOT/'runtime-v2/python.exe','-I','-S','-B',ROOT/'scripts/offline_worker.py','evaluate',direct])
    report=json.loads(direct.with_suffix('.result.json').read_text(encoding='utf-8'))
    rows.append({'test':'direct_token_assertion','status':'PASS' if report.get('error_code')=='APPCONTAINER_REQUIRED' else 'FAIL','result':report})
    # Output-anchor files are not input; an existing synthetic file is refused.
    supplied=ROOT/'private'/(tag+'-input.json');supplied.write_text('PUBLIC_SYNTHETIC_DO_NOT_PROCESS',encoding='utf-8')
    call('existing_input_rejected_before_child',[launcher,'evaluate',supplied],contains='INPUT_FILE_NOT_ACCEPTED')
    call('worker_invalid_mode_before_files',[ROOT/'runtime-v2/python.exe','-I','-S','-B',ROOT/'scripts/offline_worker.py','predict',supplied],contains='BUSINESS_INPUT_DISABLED')
    existing=ROOT/'private'/(tag+'-existing.result.json');existing.write_text('PUBLIC_SYNTHETIC_PRESERVE',encoding='utf-8')
    call('existing_result_not_overwritten',[launcher,'evaluate',existing.with_name(tag+'-existing.json')],contains='RESULT_EXISTS_PRESERVED')
    rows.append({'test':'existing_bytes_preserved','status':'PASS' if existing.read_text()=='PUBLIC_SYNTHETIC_PRESERVE' else 'FAIL'})
    # Minimal negative fixtures, NOT new repositories or installed runtimes.
    fixture=evidence/('launcher-fixtures-'+uuid.uuid4().hex)
    (fixture/'build').mkdir(parents=True);(fixture/'private').mkdir()
    shutil.copyfile(launcher,fixture/'build/LayaLauncher.exe')
    fake_launcher=fixture/'build/LayaLauncher.exe'
    anchor=fixture/'private/public.json'
    call('missing_integrity_fails_closed',[fake_launcher,'evaluate',anchor],contains='OFFLINE_INSTALLATION_SEAL_REQUIRED')
    (fixture/'build/offline-integrity.tsv').write_text('INVALID_PUBLIC_TEST_SEAL',encoding='utf-8')
    call('malformed_integrity_fails_closed',[fake_launcher,'evaluate',anchor],contains='INVALID_INSTALLATION_SEAL')
    # Preserve the previous synthetic seal before testing a hash mismatch.
    shutil.copyfile(fixture/'build/offline-integrity.tsv',fixture/'build/malformed-seal.retained.txt')
    (fixture/'public.txt').write_text('PUBLIC_SYNTHETIC',encoding='utf-8')
    (fixture/'build/offline-integrity.tsv').write_text('LAYA_OFFLINE_INTEGRITY_V1\n'+'0'*64+'\tpublic.txt\n',encoding='utf-8')
    call('hash_mismatch_fails_closed',[fake_launcher,'evaluate',anchor],contains='INSTALLATION_HASH_MISMATCH')
    result={'status':'PASS' if all(r['status']=='PASS' for r in rows) else 'FAIL','tests':rows,'business_input_enabled':False}
    path=evidence/(tag+'.json')
    with path.open('x',encoding='utf-8') as f:json.dump(result,f,ensure_ascii=False,indent=2)
    print(json.dumps({'status':result['status'],'tests':len(rows),'report':str(path),'business_input_enabled':False}))
    return 0 if result['status']=='PASS' else 1
if __name__=='__main__':
    sys.stdout.reconfigure(encoding='utf-8');p=argparse.ArgumentParser();p.add_argument('--evidence-dir',required=True);a=p.parse_args()
    e=Path(os.path.abspath(a.evidence_dir));e.mkdir(parents=True,exist_ok=True)
    raise SystemExit(main(e))