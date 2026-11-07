#!/usr/bin/env python3
"""Check the reviewed APK and its exact source inputs; never executes downloaded code."""
from pathlib import Path
import hashlib
import json
import subprocess

root = Path(__file__).resolve().parents[1]
manifest = json.loads((root / 'release/source-file-sha256-1.4.0.json').read_text())
digest = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
for name, expected in manifest['files'].items():
    path = (root / name).resolve()
    if not path.is_relative_to(root) or not path.is_file() or digest(path) != expected:
        raise SystemExit('Reviewed source input mismatch: ' + name)
apk = root / 'release/RefurbCheck-1.4.0.apk'
if digest(apk) != manifest['apkSha256']:
    raise SystemExit('Reviewed APK mismatch')
checksum = (root / 'release/RefurbCheck-1.4.0.apk.sha256').read_text().strip()
if checksum != manifest['apkSha256'] + '  RefurbCheck-1.4.0.apk':
    raise SystemExit('APK checksum sidecar mismatch')
if (root / 'release/signing-certificate-sha256-1.4.0.txt').read_text().strip() != manifest['signingCertificateSha256']:
    raise SystemExit('Certificate fingerprint mismatch')
tracked = subprocess.check_output(['git', 'ls-files'], cwd=root, text=True).splitlines()
for name in tracked:
    if name.endswith(('.p12', '.jks', '.keystore')) or 'PRIVATE-signing' in name or name.endswith('private.pem'):
        raise SystemExit('Unexpected private signing material path: ' + name)
print('Reviewed APK and', len(manifest['files']), 'source/build inputs verified.')
