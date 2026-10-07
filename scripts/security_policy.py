"""Synthetic-only safety policy; not an OS isolation substitute."""
import ctypes
import hashlib
import os
from pathlib import Path, PureWindowsPath
import re
import stat
import sys

ROOT = Path(os.path.abspath(Path(__file__).parent.parent))
FIXTURE_SHA256 = '7f3b005bc8cefcda0f176c9b0add4f783946b66e890ccfce8fc0293ef0116b0b'
MODES = frozenset(('probe', 'native-probe', 'guard-check', 'evaluate'))
OFFLINE_ENV = {
    'HF_HUB_OFFLINE':'1', 'TRANSFORMERS_OFFLINE':'1',
    'HF_HUB_DISABLE_TELEMETRY':'1', 'HF_HUB_DISABLE_IMPLICIT_TOKEN':'1',
    'HF_DATASETS_OFFLINE':'1', 'DO_NOT_TRACK':'1', 'WANDB_DISABLED':'true',
    'TOKENIZERS_PARALLELISM':'false', 'PYTHONDONTWRITEBYTECODE':'1',
}

class SecurityError(RuntimeError):
    pass

def require_mode(mode):
    # This check happens before touching the supplied path or importing ML code.
    if mode not in MODES:
        raise SecurityError('Production input is disabled; BUSINESS_INPUT_DISABLED')

def checked_path(base, relative, must_exist=False):
    """Reject escape, UNC/device/ADS, reparse points, and hard-linked files.

    This is defense in depth, not protection from a hostile same-user writer
    racing a path check. Managed deployment must protect installation ACLs.
    """
    base = Path(os.path.abspath(base))
    text = str(relative)
    win = PureWindowsPath(text)
    if (not text or win.is_absolute() or win.drive or '\\' == text[:1]
            or ':' in text or '\x00' in text):
        raise SecurityError('UNSAFE_RELATIVE_PATH')
    parts = text.replace('\\','/').split('/')
    reserved = {'CON','PRN','AUX','NUL'} | {f'{p}{i}' for p in ('COM','LPT') for i in range(1,10)}
    if any(not p or p in ('.','..') or p[-1:] in (' ','.') or p.split('.')[0].upper() in reserved for p in parts):
        raise SecurityError('UNSAFE_PATH_COMPONENT')
    target = base.joinpath(*parts)
    if os.name == 'nt' and ctypes.windll.kernel32.GetDriveTypeW(str(target.anchor)) != 3:
        raise SecurityError('LOCAL_FIXED_DRIVE_REQUIRED')
    current = Path(target.anchor)
    for part in target.parts[1:]:
        current /= part
        try:
            info = current.lstat()
        except FileNotFoundError:
            continue
        if stat.S_ISLNK(info.st_mode) or getattr(info,'st_file_attributes',0) & 0x400:
            raise SecurityError('REPARSE_POINT_DENIED')
        if stat.S_ISREG(info.st_mode) and info.st_nlink != 1:
            raise SecurityError('HARDLINK_DENIED')
    if must_exist and not target.exists():
        raise SecurityError('LOCAL_ARTIFACT_MISSING')
    return target

def result_path(anchor):
    # The argument is ONLY an unused output name. It is never an input file.
    supplied = Path(os.path.abspath(anchor))
    private = ROOT/'private'
    if supplied.parent != private or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_-]{0,90}\.json', supplied.name):
        raise SecurityError('Request must be inside private directory with a synthetic basename')
    checked = checked_path(private, supplied.name)
    if checked.exists():
        raise SecurityError('INPUT_FILE_NOT_ACCEPTED')
    result = checked_path(private, supplied.stem+'.result.json')
    if result.exists():
        raise SecurityError('RESULT_EXISTS_PRESERVED')
    return result

def configure_offline():
    # Fixed allowlisted environment supplied by the launcher; defend direct use too.
    for key in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','http_proxy','https_proxy','all_proxy',
                'HF_TOKEN','HUGGING_FACE_HUB_TOKEN','OPENAI_API_KEY','ANTHROPIC_API_KEY'):
        os.environ.pop(key, None)
    os.environ.update(OFFLINE_ENV)
    for key in ('HF_HOME','USERPROFILE','APPDATA','LOCALAPPDATA','TEMP','TMP'):
        value = os.environ.get(key)
        if not value or not Path(os.path.abspath(value)).is_relative_to(ROOT/'private'):
            raise SecurityError('PRIVATE_ENVIRONMENT_REQUIRED')

def public_fixture():
    data = checked_path(ROOT,'tests/synthetic-ko.json',True).read_bytes()
    if hashlib.sha256(data).hexdigest() != FIXTURE_SHA256:
        raise SecurityError('PUBLIC_FIXTURE_HASH_MISMATCH')
    return data

def install_audit_guard():
    attempts = []
    def guard(event, args):
        if event.startswith('socket.') and event != 'socket.__new__':
            attempts.append(event)
            raise SecurityError('NETWORK_DENIED')
        if event in ('subprocess.Popen','os.system','os.exec','os.posix_spawn','os.spawn', 'os.startfile', 'os.startfile/2'):
            attempts.append(event)
            raise SecurityError('SUBPROCESS_DENIED')
    sys.addaudithook(guard)
    return attempts