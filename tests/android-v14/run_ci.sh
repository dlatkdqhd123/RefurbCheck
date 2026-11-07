#!/usr/bin/env bash
set -euo pipefail
refurbcheck_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
refurbcheck_api="${1:?API level required}"
refurbcheck_sdk="${ANDROID_HOME:?SDK required}"
refurbcheck_adb="$refurbcheck_sdk/platform-tools/adb"
refurbcheck_avdmanager="$refurbcheck_sdk/cmdline-tools/latest/bin/avdmanager"
refurbcheck_emulator="$refurbcheck_sdk/emulator/emulator"
for refurbcheck_tool in "$refurbcheck_adb" "$refurbcheck_avdmanager" "$refurbcheck_emulator"; do
    [[ -x "$refurbcheck_tool" ]] || { printf '%s\n' "Missing executable Android SDK tool: $refurbcheck_tool" >&2; exit 1; }
done
command -v keytool >/dev/null || { printf '%s\n' 'JDK keytool is required.' >&2; exit 1; }
refurbcheck_private="$(mktemp -d "$RUNNER_TEMP/refurbcheck-test-signing.XXXXXX")"
refurbcheck_android_state=""
refurbcheck_emulator_pid=""
refurbcheck_adb_wait_pid=""
refurbcheck_cleanup() {
    if [[ -n "$refurbcheck_adb_wait_pid" ]]; then kill "$refurbcheck_adb_wait_pid" 2>/dev/null || true; fi
    if [[ -n "$refurbcheck_emulator_pid" ]]; then
        timeout 5 "$refurbcheck_adb" emu kill >/dev/null 2>&1 || true
        kill "$refurbcheck_emulator_pid" 2>/dev/null || true
    fi
    rm -rf -- "$refurbcheck_private"
    if [[ -n "$refurbcheck_android_state" ]]; then rm -rf -- "$refurbcheck_android_state"; fi
}
trap refurbcheck_cleanup EXIT
# Older command-line tools use ANDROID_SDK_HOME/.android; current tools use
# ANDROID_USER_HOME and ANDROID_AVD_HOME. Give both generations the same state.
refurbcheck_android_state="$(mktemp -d "$RUNNER_TEMP/refurbcheck-android.XXXXXX")"
export ANDROID_SDK_HOME="$refurbcheck_android_state"
export ANDROID_USER_HOME="$refurbcheck_android_state/.android"
export ANDROID_EMULATOR_HOME="$ANDROID_USER_HOME"
export ANDROID_AVD_HOME="$ANDROID_USER_HOME/avd"
mkdir -p "$ANDROID_AVD_HOME"
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
# The disposable API26+ target uses v2/v3 only. Re-adding v1 ZIP members can
# leave the old signing-block alignment inside the ZIP entry region. Keep the
# parser strict and scan the original production APK separately in the test.
"$refurbcheck_sdk/build-tools/35.0.0/apksigner" sign --ks "$refurbcheck_private/test.p12" \
    --ks-key-alias refurbcheck --ks-pass "file:$refurbcheck_private/password.txt" \
    --v1-signing-enabled false --v2-signing-enabled true --v3-signing-enabled true --v4-signing-enabled false \
    --out build/runtime-target.apk release/RefurbCheck-1.4.0.apk
python3 - <<'PY'
import zipfile,re
def signature_member(n):
    return n == 'META-INF/MANIFEST.MF' or re.fullmatch(r'META-INF/[^/]+\.(SF|RSA|EC|DSA)',n) is not None
def content(path):
    with zipfile.ZipFile(path) as z:
        return {n:z.read(n) for n in z.namelist() if not signature_member(n)}
assert content('release/RefurbCheck-1.4.0.apk')==content('build/runtime-target.apk'), 'Runtime code/resources differ from production APK'
print('Production DEX, manifest, resources and assets exactly preserved; only test signing identity differs.')
PY
python3 tests/android-v14/build_instrumentation.py --sdk-root "$refurbcheck_sdk" \
    --app-apk build/runtime-target.apk --keystore "$refurbcheck_private/test.p12" \
    --password-file "$refurbcheck_private/password.txt"
mkdir -p build/runtime-results
printf 'no\n' | "$refurbcheck_avdmanager" create avd --force --name refurbcheck_ci \
    --path "$ANDROID_AVD_HOME/refurbcheck_ci.avd" \
    --package "system-images;android-$refurbcheck_api;google_apis;x86_64" \
    2>&1 | tee build/runtime-results/avd-create.log
if [[ ! -f "$ANDROID_AVD_HOME/refurbcheck_ci.ini" || ! -f "$ANDROID_AVD_HOME/refurbcheck_ci.avd/config.ini" ]]; then
    printf '%s\n' "AVD registration or configuration missing under $ANDROID_AVD_HOME" >&2
    "$refurbcheck_avdmanager" list avd >&2 || true
    exit 1
fi
"$refurbcheck_emulator" -list-avds | tee build/runtime-results/avd-list.log
python3 - <<'PY'
from pathlib import Path
names = Path('build/runtime-results/avd-list.log').read_text().splitlines()
assert 'refurbcheck_ci' in [name.strip() for name in names], 'Emulator cannot resolve the registered refurbcheck_ci AVD'
PY
refurbcheck_emulator_failure() {
    printf '%s\n' "$1" >&2
    for refurbcheck_log in build/runtime-results/emulator.log build/runtime-results/adb-wait.log; do
        if [[ -f "$refurbcheck_log" ]]; then
            printf '%s\n' "Log: $refurbcheck_log" >&2
            tail -100 "$refurbcheck_log" >&2
        fi
    done
    exit 1
}
"$refurbcheck_emulator" -avd refurbcheck_ci -no-window -no-audio -no-boot-anim \
    -no-snapshot -gpu swiftshader_indirect -accel on -cores 2 -memory 2048 > build/runtime-results/emulator.log 2>&1 &
refurbcheck_emulator_pid=$!
timeout --kill-after=5s 180s "$refurbcheck_adb" wait-for-device > build/runtime-results/adb-wait.log 2>&1 &
refurbcheck_adb_wait_pid=$!
while kill -0 "$refurbcheck_adb_wait_pid" 2>/dev/null; do
    kill -0 "$refurbcheck_emulator_pid" 2>/dev/null || refurbcheck_emulator_failure 'Emulator exited before adb connected.'
    sleep 1
done
if ! wait "$refurbcheck_adb_wait_pid"; then
    refurbcheck_adb_wait_pid=""
    refurbcheck_emulator_failure 'adb wait-for-device failed or timed out.'
fi
refurbcheck_adb_wait_pid=""
refurbcheck_booted=false
refurbcheck_boot_deadline=$((SECONDS + 360))
while (( SECONDS < refurbcheck_boot_deadline )); do
    kill -0 "$refurbcheck_emulator_pid" 2>/dev/null || refurbcheck_emulator_failure 'Emulator exited before Android completed booting.'
    if [[ "$(timeout --kill-after=2s 10s "$refurbcheck_adb" shell getprop sys.boot_completed 2>/dev/null | tr -d '\r')" == 1 ]]; then refurbcheck_booted=true; break; fi
    sleep 2
done
[[ "$refurbcheck_booted" == true ]] || refurbcheck_emulator_failure 'Android boot did not complete before the deadline.'
"$refurbcheck_adb" shell input keyevent 82
"$refurbcheck_adb" install -r build/runtime-target.apk
"$refurbcheck_adb" install -r -t build/android-v14/RefurbCheck-v14-instrumentation.apk
timeout --kill-after=10s 600s "$refurbcheck_adb" shell am instrument -w -r io.github.refurbcheck.v14test/io.github.refurbcheck.V14Instrumentation \
    | tee build/runtime-results/instrumentation.log
refurbcheck_test_sha="$(sha256sum build/runtime-target.apk)"
refurbcheck_production_sha="$(sha256sum release/RefurbCheck-1.4.0.apk)"
python3 tests/android-v14/check_instrumentation_log.py build/runtime-results/instrumentation.log \
    --api "$refurbcheck_api" --app-sha256 "${refurbcheck_test_sha%% *}" \
    --production-sha256 "${refurbcheck_production_sha%% *}" \
    --summary-output build/runtime-results/summary.json
# The real public artifacts retain the production signing identity. Remove
# only the disposable instrumentation packages, then perform an ordinary
# in-place upgrade from the exact v1.3 release. Never uninstall between these
# two public releases, and never put the production private key in CI.
"$refurbcheck_adb" uninstall io.github.refurbcheck.v14test
"$refurbcheck_adb" uninstall io.github.refurbcheck
"$refurbcheck_sdk/build-tools/35.0.0/apksigner" verify --verbose --print-certs release/RefurbCheck-1.3.0.apk > build/runtime-results/upgrade-source-signature.txt
"$refurbcheck_sdk/build-tools/35.0.0/apksigner" verify --verbose --print-certs release/RefurbCheck-1.4.0.apk > build/runtime-results/upgrade-target-signature.txt
"$refurbcheck_adb" install release/RefurbCheck-1.3.0.apk | tee build/runtime-results/upgrade-source-install.txt
"$refurbcheck_adb" shell dumpsys package io.github.refurbcheck > build/runtime-results/upgrade-source-package.txt
"$refurbcheck_adb" shell am start -W -a android.intent.action.MAIN -c android.intent.category.LAUNCHER \
    -n io.github.refurbcheck/.MainActivity > build/runtime-results/upgrade-source-launch.txt
"$refurbcheck_adb" install -r release/RefurbCheck-1.4.0.apk | tee build/runtime-results/upgrade-replace-install.txt
"$refurbcheck_adb" shell dumpsys package io.github.refurbcheck > build/runtime-results/upgrade-target-package.txt
"$refurbcheck_adb" shell am start -W -a android.intent.action.MAIN -c android.intent.category.LAUNCHER \
    -n io.github.refurbcheck/.MainActivity > build/runtime-results/release-launch.txt
"$refurbcheck_adb" shell pidof io.github.refurbcheck > build/runtime-results/release-pid.txt
# The UI evidence is captured from the original production-signed APK after
# the upgrade, not from the instrumentation target or a reconstructed mockup.
timeout --kill-after=5s 40s "$refurbcheck_adb" shell uiautomator dump --compressed /sdcard/refurbcheck-v14-ui.xml \
    > build/runtime-results/production-ui-dump.log
"$refurbcheck_adb" pull /sdcard/refurbcheck-v14-ui.xml build/runtime-results/production-one-run.xml
"$refurbcheck_adb" exec-out screencap -p > build/runtime-results/production-one-run.png
"$refurbcheck_adb" shell rm /sdcard/refurbcheck-v14-ui.xml
python3 tests/android-v14/check_upgrade.py --results build/runtime-results \
    --source-apk release/RefurbCheck-1.3.0.apk --target-apk release/RefurbCheck-1.4.0.apk --api "$refurbcheck_api"
