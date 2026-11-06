#!/usr/bin/env python3
"""Rebuild the pinned AOSP Android 16 apksig Java subset; no network or signing keys."""
from pathlib import Path
import hashlib
import json
import shutil
import subprocess
import zipfile

root = Path(__file__).resolve().parents[1]
metadata = json.loads((root / 'app/libs/apksig-aosp-16.PROVENANCE.json').read_text())
archive = root / 'third_party/apksig/aosp-android16-source.zip'
if hashlib.sha256(archive.read_bytes()).hexdigest() != metadata['sourceArchiveSha256']:
    raise SystemExit('Pinned source archive digest mismatch')
build = root / 'build/apksig-rebuild'
if build.exists():
    shutil.rmtree(build)
source, classes = build / 'source', build / 'classes'
source.mkdir(parents=True)
classes.mkdir()
with zipfile.ZipFile(archive) as inputs:
    for entry in inputs.infolist():
        path = Path(entry.filename)
        if path.is_absolute() or '..' in path.parts:
            raise SystemExit('Unsafe source archive path')
        inputs.extract(entry, source)
files = sorted((source / 'src/main/java').rglob('*.java'))
if len(files) != metadata['javaSources']:
    raise SystemExit('Source count mismatch')
subprocess.run(['java', '--module', 'jdk.compiler/com.sun.tools.javac.Main',
                '--release', '8', '-encoding', 'UTF-8', '-d', str(classes)]
               + [str(path) for path in files], check=True)
jar = build / 'apksig-aosp-16.jar'
with zipfile.ZipFile(jar, 'w', compression=zipfile.ZIP_DEFLATED) as output:
    for path in sorted(classes.rglob('*.class')):
        info = zipfile.ZipInfo(path.relative_to(classes).as_posix(), (2026, 11, 7, 0, 0, 0))
        info.compress_type = zipfile.ZIP_DEFLATED
        output.writestr(info, path.read_bytes())
actual = hashlib.sha256(jar.read_bytes()).hexdigest()
print('Rebuilt JAR SHA-256:', actual)
if actual != metadata['jarSha256']:
    raise SystemExit('JAR differs; review compiler version before changing the pinned artifact')
print('Pinned bundled JAR reproduced exactly.')
