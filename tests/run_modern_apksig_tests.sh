#!/usr/bin/env bash
set -euo pipefail
refurbcheck_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
python3 - "$refurbcheck_root" <<'PY'
import hashlib,json,sys
from pathlib import Path
r=Path(sys.argv[1]); p=json.loads((r/'app/libs/apksig-aosp-16.PROVENANCE.json').read_text())
assert hashlib.sha256((r/'app/libs/apksig-aosp-16.jar').read_bytes()).hexdigest()==p['jarSha256']
for name,digest in p['fixtures'].items():
    assert hashlib.sha256((r/'tests/apksig-fixtures'/name).read_bytes()).hexdigest()==digest,name
PY
mkdir -p "$refurbcheck_root/build/modern-apksig-tests"
java --module jdk.compiler/com.sun.tools.javac.Main --release 8 -encoding UTF-8 \
  -classpath "$refurbcheck_root/app/libs/apksig-aosp-16.jar" -d "$refurbcheck_root/build/modern-apksig-tests" \
  "$refurbcheck_root/app/src/main/java/io/github/refurbcheck/ApkEvidence.java" "$refurbcheck_root/tests/ModernApksigTests.java"
java -classpath "$refurbcheck_root/build/modern-apksig-tests:$refurbcheck_root/app/libs/apksig-aosp-16.jar" \
  io.github.refurbcheck.ModernApksigTests "$refurbcheck_root/tests/apksig-fixtures"
