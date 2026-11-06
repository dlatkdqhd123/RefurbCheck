#!/usr/bin/env bash
set -euo pipefail

refurbcheck_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
refurbcheck_sdk="${ANDROID_SDK_ROOT:-${ANDROID_HOME:-${refurbcheck_root}/../android-toolchain/sdk}}"
refurbcheck_android_jar="${refurbcheck_sdk}/platforms/android-35/android.jar"
refurbcheck_jar="${refurbcheck_root}/app/libs/apksig-aosp-16.jar"
refurbcheck_classes="${refurbcheck_root}/build/apk-inspection-compile"
refurbcheck_stubs="${refurbcheck_root}/build/apk-inspection-stubs"
refurbcheck_fixture_dir="${refurbcheck_root}/build/apk-test-fixtures"
refurbcheck_java="${REFURBCHECK_JAVA:-java}"
refurbcheck_apk="${REFURBCHECK_TEST_APK:-${refurbcheck_root}/release/RefurbCheck-1.2.0.apk}"
if [[ ! -f "$refurbcheck_apk" && -z "${REFURBCHECK_TEST_APK:-}" ]]; then
    refurbcheck_apk="${refurbcheck_root}/release/RefurbCheck-1.1.0.apk"
fi
for refurbcheck_file in "$refurbcheck_android_jar" "$refurbcheck_jar" "$refurbcheck_apk"; do
    [[ -f "$refurbcheck_file" ]] || { printf '%s\n' "Missing test input: $refurbcheck_file" >&2; exit 1; }
done
refurbcheck_hash="$(sha256sum -- "$refurbcheck_jar")"
[[ "${refurbcheck_hash%% *}" == "83d7d7fec92ca21214d180e232a4594d2a1b6ee3b186a7b8ebf338d95e317040" ]] || {
    printf '%s\n' "Bundled apksig jar hash mismatch; refusing to execute it." >&2; exit 1;
}
mkdir -p -- "$refurbcheck_classes" "$refurbcheck_stubs/io/github/refurbcheck" "$refurbcheck_fixture_dir"
# Isolate this test from app orchestration; no Android behavior is mocked by this interface stub.
printf '%s\n' 'package io.github.refurbcheck; public final class ScanEngine { public interface Progress { void update(String stage); } }' \
    > "$refurbcheck_stubs/io/github/refurbcheck/ScanEngine.java"
python3 - "$refurbcheck_apk" "$refurbcheck_fixture_dir" <<'PY'
from pathlib import Path
import struct
import sys
import zipfile
source, target = Path(sys.argv[1]), Path(sys.argv[2])
original = source.read_bytes()
with zipfile.ZipFile(source) as archive:
    entry = archive.getinfo("classes.dex")
    name_size, extra_size = struct.unpack_from("<HH", original, entry.header_offset + 26)
    offset = entry.header_offset + 30 + name_size + extra_size + entry.compress_size // 2
modified = bytearray(original)
modified[offset] ^= 1
(target / "signed.apk").write_bytes(original)
(target / "tampered.apk").write_bytes(modified)
PY
"$refurbcheck_java" --module jdk.compiler/com.sun.tools.javac.Main --release 8 -encoding UTF-8 \
    -sourcepath "$refurbcheck_stubs" -classpath "$refurbcheck_android_jar:$refurbcheck_jar" -d "$refurbcheck_classes" \
    "$refurbcheck_root/app/src/main/java/io/github/refurbcheck/ApkEvidence.java" \
    "$refurbcheck_root/app/src/main/java/io/github/refurbcheck/ApkInspection.java" \
    "$refurbcheck_root/app/src/main/java/io/github/refurbcheck/MalwareEvidence.java" \
    "$refurbcheck_root/app/src/main/java/io/github/refurbcheck/MalwareInspection.java" \
    "$refurbcheck_root/app/src/main/java/io/github/refurbcheck/MalwareCatalog.java" \
    "$refurbcheck_root/app/src/main/java/io/github/refurbcheck/CatalogUpdateConfig.java" \
    "$refurbcheck_root/app/src/main/java/io/github/refurbcheck/CatalogUpdateVerifier.java" \
    "$refurbcheck_root/app/src/main/java/io/github/refurbcheck/CatalogUpdateStore.java" \
    "$refurbcheck_root/app/src/main/java/io/github/refurbcheck/CatalogUpdateManager.java" \
    "$refurbcheck_root/app/src/main/java/io/github/refurbcheck/ReportJson.java" \
    "$refurbcheck_root/app/src/main/java/io/github/refurbcheck/ScanReport.java" \
    "$refurbcheck_root/app/src/main/java/io/github/refurbcheck/Finding.java" \
    "$refurbcheck_stubs/io/github/refurbcheck/ScanEngine.java" \
    "$refurbcheck_root/tests/ApkInspectionTests.java"
"$refurbcheck_java" -classpath "$refurbcheck_classes:$refurbcheck_jar:$refurbcheck_android_jar" \
    io.github.refurbcheck.ApkInspectionTests "$refurbcheck_root/app/src/main/assets" \
    "$refurbcheck_fixture_dir/signed.apk" "$refurbcheck_fixture_dir/tampered.apk"
