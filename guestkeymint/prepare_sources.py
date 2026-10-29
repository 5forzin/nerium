"""Prepare pinned production AOSP sources; never download key fixtures."""
import base64
import concurrent.futures
import hashlib
import json
from pathlib import Path
import re
import sys
import time
import urllib.request

CACHE = Path(sys.argv[1])
SOURCES = CACHE / 'guest-sources'
PREPARED = CACHE / 'guest-prepared'
HAL = CACHE / 'hal-research'
CUTTLEFISH = 'f9854dd87cb0c309157ccb065af1cc7d3ea20b09'
KEYMASTER = '8729d4dd86c0bfec54c34610aa1c35f3d109b8a6'
INTERFACES = '40e9f1537e308ed49e3b561ce333e3f2bb64f31e'
NATIVE = 'bfcf75076e562945bae131a4929f29a90d0d2481'
manifest = {}

def get(url):
    for attempt in range(6):
        try:
            with urllib.request.urlopen(url, timeout=45) as response:
                return response.read()
        except Exception:
            if attempt == 5:
                raise
            time.sleep(attempt + 1)

def fetch(repo, revision, path, target):
    url = f'https://android.googlesource.com/{repo}/+/{revision}/{path}?format=TEXT'
    if not target.exists():
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(base64.b64decode(get(url)))
    manifest[str(target.relative_to(CACHE)).replace('\\', '/')] = {
        'source': url, 'sha256': hashlib.sha256(target.read_bytes()).hexdigest()}

def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8', newline='\n')

REMOTE_NAMES = ['remote_keymaster', 'remote_keymint_device', 'remote_keymint_operation',
                'remote_shared_secret', 'remote_secure_clock']
for name in REMOTE_NAMES:
    for extension in ['h', 'cpp']:
        f = name + '.' + extension
        fetch('device/google/cuttlefish', CUTTLEFISH, 'guest/hals/keymint/remote/' + f,
              SOURCES / 'remote' / f)
for f in ['ng/KeyMintUtils.cpp', 'ng/include/KeyMintUtils.h']:
    fetch('platform/system/keymaster', KEYMASTER, f, SOURCES / 'keymaster' / f)

def frozen(package, version):
    root = f'security/{package}/aidl/aidl_api/android.hardware.security.{package}/{version}/'
    def walk(path):
        entries = json.loads(get(f'https://android.googlesource.com/platform/hardware/interfaces/+/{INTERFACES}/{root}{path}?format=JSON')[4:])['entries']
        for entry in entries:
            name = path + entry['name']
            target = HAL / 'aidl' / package / name
            if entry['type'] == 'tree':
                walk(name + '/')
            elif name.endswith('.aidl') or name == '.hash':
                fetch('platform/hardware/interfaces', INTERFACES, root + name, target)
    # Existing complete source trees are supplied by the platform audit.
    target = HAL / 'aidl' / package
    expected = {'keymint': 24, 'secureclock': 3, 'sharedsecret': 2, 'rkp': 5}[package]
    if len(list(target.rglob('*.aidl'))) != expected or not (target / '.hash').exists():
        walk('')
    for item in target.rglob('*'):
        if item.is_file():
            manifest[str(item.relative_to(CACHE)).replace('\\', '/')] = {
                'revision': INTERFACES, 'sha256': hashlib.sha256(item.read_bytes()).hexdigest()}

frozen('keymint', 3)
frozen('secureclock', 1)
frozen('sharedsecret', 1)
frozen('rkp', 3)
for name in ['binder_manager.h', 'binder_process.h', 'binder_stability.h', 'binder_ibinder_platform.h', 'binder_parcel_platform.h']:
    fetch('platform/frameworks/native', NATIVE, 'libs/binder/ndk/include_platform/android/' + name,
          HAL / 'include/android' / name)

remote = PREPARED / 'guest/hals/keymint/remote'
for source in (SOURCES / 'remote').glob('*'):
    if source.name not in {n + '.' + e for n in REMOTE_NAMES for e in ['h', 'cpp']}:
        continue
    text = source.read_text()
    text = text.replace('#include <keymaster/android_keymaster.h>\n', '')
    text = text.replace('#include <keymaster/contexts/pure_soft_keymaster_context.h>\n', '')
    text = text.replace('#include <keymaster/keymaster_configuration.h>\n', '')
    if source.name == 'remote_keymaster.h':
        text = text.replace('#include "common/libs/security/keymaster_channel_sharedfd.h"', '#include "guest_channel.h"')
        text = text.replace('cuttlefish::SharedFdKeymasterChannel', 'androidlab::GuestChannel')
        text = text.replace('  bool Initialize();\n', '')
    elif source.name == 'remote_keymaster.cpp':
        text = text.replace('cuttlefish::SharedFdKeymasterChannel', 'androidlab::GuestChannel')
        text = text.replace('#include <android-base/logging.h>\n', '')
        text = text.replace('#include <android-base/properties.h>\n', '')
        text = text.replace('#include <android-base/strings.h>\n', '')
        begin = text.index('  if (!channel_->SendRequest(')
        end = text.index('\nvoid RemoteKeymaster::GetVersion', begin)
        text = text[:begin] + '  channel_->Exchange(command, req, rsp);\n}\n' + text[end:]
    elif source.name == 'remote_keymint_device.cpp':
        text = text.replace('  info->versionNumber = 1;', '  info->versionNumber = 3;')
        text = text.replace('"RemoteKeyMintDevice"', '"AndroidLab Windows CNG"')
        text = text.replace('"Google"', '"Android Device Lab"')
        begin = text.index('  if (keyMintSecurityLevel != SecurityLevel::SOFTWARE) {')
        end = text.index('  KeyCharacteristics keystoreEnforced', begin)
        text = text[:begin] + text[end:]
        begin = text.index('  if (!rootOfTrust) {', text.index('ScopedAStatus RemoteKeyMintDevice::getRootOfTrust('))
        end = text.index('\n}\n', begin)
        text = text[:begin] + '  (void)challenge;\n  (void)rootOfTrust;\n  return kmError2ScopedAStatus(KM_ERROR_UNIMPLEMENTED);' + text[end:]
        text = text.replace('  // There\'s nothing to be done to delete software key blobs.\n', '')
    write(remote / source.name, text)
for source in (SOURCES / 'keymaster').rglob('*'):
    if source.is_file():
        write(PREPARED / 'keymaster' / source.relative_to(SOURCES / 'keymaster'), source.read_text())
write(CACHE / 'guest-source-manifest.json', json.dumps({
    'schema_version': 1, 'cuttlefish_revision': CUTTLEFISH,
    'keymaster_revision': KEYMASTER, 'interfaces_revision': INTERFACES,
    'native_revision': NATIVE, 'files': manifest}, indent=2) + '\n')
print(PREPARED)
