"""Read-only Git exclusion assertions; no add, commit, remote, or publication."""
from pathlib import Path
import json
import subprocess
import sys
ROOT=Path(__file__).absolute().parents[1]
excluded=['runtime/python.exe','runtime-v2/python.exe','models/public-model.bin','artifacts/public.whl','private/synthetic.result.json','build/LayaLauncher.exe','unreviewed-root-document.txt','.env','docs/example.key','tests/example.result.json','scripts/__pycache__/test.pyc']
public=['.gitignore','README.md','NOTICE.md','dependency-lock.json','model-manifest.json','prepared-model-manifest.json','docs/GUIDE.ko.md','docs/INSTALL.ko.md','docs/SECURITY-STATUS.ko.md','scripts/security_policy.py','tests/test_security.py']
cmd=['git','check-ignore','--no-index','--stdin','-z']
# Binary NUL framing prevents Windows CRLF translation from changing filenames.
r=subprocess.run(cmd,cwd=ROOT,input=('\0'.join(excluded+public)+'\0').encode('utf-8'),capture_output=True)
actual={name for name in r.stdout.decode('utf-8').split('\0') if name}
assert r.returncode==0, 'git check-ignore failed'
assert actual==set(excluded), 'Public/private path selection mismatch'
print(json.dumps({'status':'PASS','assertions':len(excluded)+len(public),'command':cmd,'child_exit_code':r.returncode,'meaning':'Git exclusion patterns only; not public release approval'}))