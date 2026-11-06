#!/usr/bin/env bash
set -euo pipefail
refurbcheck_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
refurbcheck_api="${1:?API level required}"
refurbcheck_sdk="${ANDROID_HOME:?SDK required}"
refurbcheck_private="$(mktemp -d "$RUNNER_TEMP/refurbcheck-test-signing.XXXXXX")"
trap 'rm -rf -- "$refurbcheck_private"; adb emu kill >/dev/null 2>&1 || true' EXIT
export REFURBCHECK_TEST_PRIVATE="$refurbcheck_private"
python3 - <<'PY'
from pathlib import Path
import os,secrets
p=Path(os.environ['REFURBCHECK_TEST_PRIVATE'])/'password.txt'
p.write_text(secrets.token_urlsafe(32)+'\n'); p.chmod(0o600)
PY
keytool -genkeypair -keystore "$refurbcheck_private/test.p12" -storetype PKCS12 \
    -storepass:file "$refurbcheck_private/password.txt" -keypass:file "$refurbcheck_private/password.txt" \
    -alias refurbcheck -keyalg RSA -keysize 3072 -validity 2 -dname 'CN=Ephemeral RefurbCheck CI test only' >/dev/null 2>&1
cd "$refurbcheck_root"
# Build compiler output for the separate instrumentation code. The runtime
# target below comes from the reviewed release APK, not this fresh compilation.
python3 tools/build_apk.py --sdk-root "$refurbcheck_sdk" --keystore "$refurbcheck_private/test.p12" \
    --password-file "$refurbcheck_private/password.txt" --output build/ci-compilation.apk
"$refurbcheck_sdk/build-tools/35.0.0/apksigner" sign --ks "$refurbcheck_private/test.p12" \
    --ks-key-alias refurbcheck --ks-pass "file:$refurbcheck_private/password.txt" \
    --v2-signing-enabled true --v3-signing-enabled true --v4-signing-enabled false \
    --out build/runtime-target.apk release/RefurbCheck-1.3.0.apk
python3 - <<'PY'
import zipfile,re
def signature_member(n):
    return n == 'META-INF/MANIFEST.MF' or re.fullmatch(r'META-INF/[^/]+\.(SF|RSA|EC|DSA)',n) is not None
def content(path):
    with zipfile.ZipFile(path) as z:
        return {n:z.read(n) for n in z.namelist() if not signature_member(n)}
assert content('release/RefurbCheck-1.3.0.apk')==content('build/runtime-target.apk'), 'Runtime code/resources differ from production APK'
print('Production DEX, manifest, resources and assets exactly preserved; only test signing identity differs.')
PY
python3 tests/android-v13/build_instrumentation.py --sdk-root "$refurbcheck_sdk" \
    --app-apk build/runtime-target.apk --keystore "$refurbcheck_private/test.p12" \
    --password-file "$refurbcheck_private/password.txt"
mkdir -p build/runtime-results
echo no | avdmanager create avd --force --name refurbcheck_ci \
    --package "system-images;android-$refurbcheck_api;google_apis;x86_64"
"$refurbcheck_sdk/emulator/emulator" -avd refurbcheck_ci -no-window -no-audio -no-boot-anim \
    -no-snapshot -gpu swiftshader_indirect -accel on -cores 2 -memory 2048 > build/runtime-results/emulator.log 2>&1 &
timeout 180 adb wait-for-device
refurbcheck_booted=false
for refurbcheck_attempt in $(seq 1 180); do
    if [[ "$(adb shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == 1 ]]; then refurbcheck_booted=true; break; fi
    sleep 2
done
[[ "$refurbcheck_booted" == true ]] || { tail -80 build/runtime-results/emulator.log; exit 1; }
adb shell input keyevent 82
adb install -r build/runtime-target.apk
adb install -r -t build/android-v13/RefurbCheck-v13-instrumentation.apk
timeout 240 adb shell am instrument -w io.github.refurbcheck.v13test/io.github.refurbcheck.V13Instrumentation \
    | tee build/runtime-results/instrumentation.log
refurbcheck_test_sha="$(sha256sum build/runtime-target.apk)"
python3 tests/android-v13/check_instrumentation_log.py build/runtime-results/instrumentation.log \
    --api "$refurbcheck_api" --app-sha256 "${refurbcheck_test_sha%% *}" \
    --summary-output build/runtime-results/summary.json
# Install and launch the exact distributed APK after removing only the
# disposable test target. No production signing key ever enters this job.
adb uninstall io.github.refurbcheck.v13test
adb uninstall io.github.refurbcheck
adb install release/RefurbCheck-1.3.0.apk
adb shell am start -W -n io.github.refurbcheck/.MainActivity > build/runtime-results/release-launch.txt
adb shell pidof io.github.refurbcheck > build/runtime-results/release-pid.txt
python3 - <<'PY'
from pathlib import Path
r=Path('build/runtime-results')
assert 'Status: ok' in (r/'release-launch.txt').read_text()
assert (r/'release-pid.txt').read_text().strip()
print('Exact production APK installed and launcher started successfully.')
PY
