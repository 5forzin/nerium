import base64
import concurrent.futures
import hashlib
import io
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import tarfile
import time
import urllib.request

CACHE = Path(sys.argv[1])
SOURCES = CACHE / 'sources'
KEYMASTER = '8729d4dd86c0bfec54c34610aa1c35f3d109b8a6'
BORINGSSL = '32b51305debe43e38e7bf2c2b13c4ebf3b474e80'
CPPBOR = '345280db59917d2b7085a4bd5cadab3f6935bc93'
HARDWARE = '32748ddb39cf99296ff35d374b15f04b4522e85c'

def get(url):
    for attempt in range(5):
        try:
            with urllib.request.urlopen(url, timeout=60) as response:
                return response.read()
        except Exception:
            if attempt == 4:
                raise
            time.sleep(attempt + 1)

def gitiles(path, binary=False, repo='platform/system/keymaster', revision=KEYMASTER):
    raw = get(f'https://android.googlesource.com/{repo}/+/{revision}/{path}?format=' + ('TEXT' if binary else 'JSON'))
    return base64.b64decode(raw) if binary else json.loads(raw[4:])

def save(path, content):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content)

def fetch_keymaster():
    selected = ['Android.bp', 'NOTICE']
    def walk(path):
        for entry in gitiles(path)['entries']:
            child = path + entry['name']
            if entry['type'] == 'tree':
                walk(child + '/')
            elif child.endswith(('.h', '.cpp', '.c')) and not child.endswith('soft_attestation_cert.cpp'):
                selected.append(child)
    for directory in ['include/', 'android_keymaster/', 'contexts/', 'key_blob_utils/', 'km_openssl/', 'cppcose/']:
        walk(directory)
    def download(path):
        dest = SOURCES / 'keymaster' / path
        if not dest.exists():
            save(dest, gitiles(path, True))
    with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
        list(pool.map(download, selected))

def github_sources(repository, revision, name, allow):
    destination = SOURCES / name
    marker = destination / '.revision'
    if marker.exists() and marker.read_text() == revision + ':production-v2':
        return
    result = subprocess.run(['gh', 'api', f'repos/{repository}/tarball/{revision}'], capture_output=True, check=True)
    with tarfile.open(fileobj=io.BytesIO(result.stdout), mode='r:gz') as archive:
        for entry in archive:
            relative = '/'.join(entry.name.split('/')[1:])
            if entry.isfile() and allow(relative):
                save(destination / relative, archive.extractfile(entry).read())
    save(marker, (revision + ':production-v2').encode())

CACHE.mkdir(parents=True, exist_ok=True)
fetch_keymaster()
# Only production BoringSSL crypto sources and headers; no test vectors or fixture keys.
github_sources('google/boringssl', BORINGSSL, 'boringssl', lambda p:
    (p.startswith(('crypto/', 'include/', 'third_party/fiat/')) and p.endswith(('.c', '.cc', '.h', '.inc'))
     and not re.search(r'(^|/)(test|testdata|fipsmodule/.*test)(/|\.)|_test\.', p)) or p in ['LICENSE'])
def fetch_cppbor(path):
    for entry in gitiles(path, repo='platform/system/libcppbor', revision=CPPBOR)['entries']:
        child = path + entry['name']
        if entry['type'] == 'tree':
            fetch_cppbor(child + '/')
        elif child.endswith(('.h', '.cpp')):
            save(SOURCES / 'cppbor' / child,
                 gitiles(child, True, 'platform/system/libcppbor', CPPBOR))
for path in ['include/', 'src/']:
    fetch_cppbor(path)
save(SOURCES / 'cppbor' / '.revision', CPPBOR.encode())
for path in ['include/hardware/keymaster_defs.h', 'include/hardware/hw_auth_token.h',
             'include/hardware/keymaster_common.h', 'include/hardware/keymaster1.h',
             'include/hardware/keymaster2.h', 'include/hardware/hardware.h']:
    dest = SOURCES / 'hardware' / path
    if not dest.exists():
        save(dest, gitiles(path, True, 'platform/hardware/libhardware', HARDWARE))
for path in ['sources.mk', 'err_data.c']:
    save(SOURCES / 'boringssl' / path, gitiles(path, True, 'platform/external/boringssl',
                                             'd513cbc24acec3bfefe3fccb0d963bfcea876a03'))
makefile = (SOURCES / 'boringssl' / 'sources.mk').read_text()
crypto = re.search(r'crypto_sources\s*:=\s*\\\n(.*?)(?:\n\s*\n|\Z)', makefile, re.S).group(1)
crypto_paths = re.findall(r'(?:src/)?(?:crypto/[^\s\\]+\.c|err_data\.c)', crypto)
save(SOURCES / 'boringssl' / 'crypto_sources.cmake',
     ('set(BORINGSSL_CRYPTO_SOURCES\n' + ''.join('  "${BORINGSSL_DIR}/' + p.removeprefix('src/') + '"\n'
                                              for p in crypto_paths) + ')\n').encode())
manifest = {'keymaster': KEYMASTER, 'boringssl': BORINGSSL, 'cppbor': CPPBOR, 'hardware': HARDWARE,
            'files': {str(p.relative_to(SOURCES)).replace('\\', '/'): hashlib.sha256(p.read_bytes()).hexdigest()
                      for p in sorted(SOURCES.rglob('*')) if p.is_file()}}
save(CACHE / 'source-manifest.json', (json.dumps(manifest, indent=2) + '\n').encode())
print(json.dumps({'source_files': len(manifest['files']), 'manifest': str(CACHE / 'source-manifest.json')}))
