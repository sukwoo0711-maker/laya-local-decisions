"""Public-synthetic unit/negative tests. All artifacts retained, never deleted."""
import argparse
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch
import uuid
import zipfile
ROOT=Path(__file__).absolute().parents[1]
sys.path.insert(0,str(ROOT/'scripts'))
import security_policy as policy
import prepare
import offline_worker

class SecurityTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.base=EVIDENCE/('unit-fixtures-'+uuid.uuid4().hex)
        cls.base.mkdir(parents=True)
    def folder(self):
        p=self.base/uuid.uuid4().hex;p.mkdir();return p
    def test_reject_path_variants(self):
        for name in ('../escape','a/../../b','/absolute','C:\\outside','C:relative','\\\\server\\share','a:stream','a/','a//b','a/./b','trailing.','trailing ','NUL.txt','COM1','..\\escape'):
            with self.subTest(name=name),self.assertRaises(policy.SecurityError):policy.checked_path(self.base,name)
    def test_regular_local_path(self):
        p=self.folder();f=p/'public.txt';f.write_text('PUBLIC_SYNTHETIC',encoding='utf-8')
        self.assertEqual(policy.checked_path(p,'public.txt',True),f)
    def test_actual_hardlink_rejected(self):
        p=self.folder();f=p/'original.txt';f.write_text('PUBLIC_SYNTHETIC',encoding='utf-8');os.link(f,p/'linked.txt')
        with self.assertRaisesRegex(policy.SecurityError,'HARDLINK_DENIED'):policy.checked_path(p,'linked.txt')
    def test_actual_junction_rejected(self):
        p=self.folder();target=p/'target';target.mkdir();link=p/'junction'
        cmd=['cmd.exe','/d','/c','mklink','/J',str(link),str(target)]
        r=subprocess.run(cmd,capture_output=True,text=True,encoding='utf-8',errors='replace')
        with (p/'junction-command.json').open('x',encoding='utf-8') as f:json.dump({'command':cmd,'cwd':os.getcwd(),'exit_code':r.returncode,'output':r.stdout+r.stderr},f)
        if r.returncode:self.skipTest('Junction prerequisite unavailable; exact command retained')
        with self.assertRaisesRegex(policy.SecurityError,'REPARSE_POINT_DENIED'):policy.checked_path(p,'junction/file.txt')
    def test_fixed_fixture_hash(self):
        self.assertEqual(hashlib.sha256(policy.public_fixture()).hexdigest(),policy.FIXTURE_SHA256)
    def test_tampered_synthetic_fixture_refused(self):
        p=self.folder();(p/'tests').mkdir();(p/'tests/synthetic-ko.json').write_text('{"public":"tampered"}',encoding='utf-8')
        with patch.object(policy,'ROOT',p),self.assertRaisesRegex(policy.SecurityError,'PUBLIC_FIXTURE_HASH_MISMATCH'):policy.public_fixture()
    def test_business_mode_before_path_or_model(self):
        with patch.object(sys,'argv',['worker','predict','PUBLIC_SENTINEL_NOT_TO_BE_READ']),patch.object(offline_worker,'result_path') as path,patch.object(offline_worker,'evaluate') as model:
            self.assertEqual(offline_worker.main(),1);path.assert_not_called();model.assert_not_called()
    def test_output_anchor_not_input(self):
        p=self.folder();(p/'private').mkdir();(p/'private/synthetic.json').write_text('PUBLIC_SYNTHETIC_INPUT',encoding='utf-8')
        with patch.object(policy,'ROOT',p),self.assertRaisesRegex(policy.SecurityError,'INPUT_FILE_NOT_ACCEPTED'):policy.result_path(p/'private/synthetic.json')
    def test_result_is_preserved(self):
        p=self.folder();(p/'private').mkdir();f=p/'private/test.result.json';f.write_text('PRESERVE',encoding='utf-8')
        with patch.object(policy,'ROOT',p),self.assertRaisesRegex(policy.SecurityError,'RESULT_EXISTS_PRESERVED'):policy.result_path(p/'private/test.json')
        self.assertEqual(f.read_text(),'PRESERVE')
    def test_safe_download_url(self):
        self.assertEqual(prepare.validate_url(prepare.PYTHON['url']),prepare.PYTHON['url'])
    def test_unsafe_download_urls(self):
        for url in ('http://www.python.org/file','https://attacker.invalid/file','https://user:password@www.python.org/file','https://www.python.org:444/file','file:///C:/file','https://www.python.org/file#fragment'):
            with self.subTest(url=url),self.assertRaises(ValueError):prepare.validate_url(url)
    def test_archive_traversal_and_symlink(self):
        for name,symlink in (('../escape.txt',False),('C:/escape.txt',False),('valid-link',True)):
            p=self.folder();archive=p/'public.zip';target=p/'target';target.mkdir()
            with zipfile.ZipFile(archive,'w') as z:
                info=zipfile.ZipInfo(name)
                if symlink:info.external_attr=(0o120777<<16)
                z.writestr(info,b'PUBLIC_SYNTHETIC')
            with self.assertRaises((ValueError,policy.SecurityError)):prepare.extract(archive,target)
    def test_safe_archive_positive(self):
        p=self.folder();archive=p/'public.zip';target=p/'target';target.mkdir()
        with zipfile.ZipFile(archive,'w') as z:z.writestr('nested/public.txt',b'PUBLIC_SYNTHETIC')
        prepare.extract(archive,target)
        self.assertEqual((target/'nested/public.txt').read_bytes(),b'PUBLIC_SYNTHETIC')
    def test_install_never_downloads(self):
        with patch.object(prepare,'verify_assets',return_value=0),patch.object(prepare,'ROOT',ROOT),patch.object(prepare,'download') as download, self.assertRaisesRegex(ValueError,'INSTALLATION_EXISTS_PRESERVED'):
            prepare.install()
        download.assert_not_called()

if __name__=='__main__':
    sys.stdout.reconfigure(encoding='utf-8');sys.stderr.reconfigure(encoding='utf-8')
    p=argparse.ArgumentParser();p.add_argument('--evidence-dir',required=True);a=p.parse_args()
    EVIDENCE=Path(os.path.abspath(a.evidence_dir));EVIDENCE.mkdir(parents=True,exist_ok=True)
    result=unittest.TextTestRunner(verbosity=2).run(unittest.defaultTestLoader.loadTestsFromTestCase(SecurityTests))
    print(json.dumps({'status':'PASS' if result.wasSuccessful() and not result.skipped else 'FAIL' if not result.wasSuccessful() else 'NOT_RUN','tests_run':result.testsRun,'failures':len(result.failures),'errors':len(result.errors),'skipped':len(result.skipped),'business_input_enabled':False}))
    raise SystemExit(0 if result.wasSuccessful() and not result.skipped else 1)