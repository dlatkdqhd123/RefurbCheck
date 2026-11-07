# Android v1.3 runtime smoke tests

This is a **separate test-only instrumentation APK**, not a production feature.
It targets the installed `io.github.refurbcheck` APK and must be signed with that
APK's certificate. It exposes no activity, service, provider or production test
endpoint. Use disposable API 26 and API 36 emulators for this workflow.

## Build and run

First build the target with `tools/build_apk.py`. Its compiled classes must remain
at `build/manual/classes` (or provide `--app-classes`). Use the same external
keystore and password file for the target and test APK. Private keys are neither
copied into the repository nor packaged in either APK.

```bash
python3 tests/android-v13/build_instrumentation.py \
  --sdk-root "$ANDROID_SDK_ROOT" \
  --app-apk dist/RefurbCheck-1.3.0.apk \
  --keystore /private/refurbcheck.p12 \
  --password-file /private/password.txt

adb install -r dist/RefurbCheck-1.3.0.apk
adb install -r -t build/android-v13/RefurbCheck-v13-instrumentation.apk
adb shell am instrument -w -r io.github.refurbcheck.v13test/io.github.refurbcheck.V13Instrumentation > android-v13.log
python3 tests/android-v13/check_instrumentation_log.py android-v13.log \
  --api 26 \
  --app-sha256 "<SHA-256 of the target APK>" \
  --production-sha256 "<SHA-256 of release/RefurbCheck-1.3.0.apk>" \
  --summary-output android-v13-summary.json
```

The SDK build requires platform 35, build tools 35.0.0 and JDK 17. A future run
using an expired signed catalog must refresh the authorized catalog first;
tests do not disable the production freshness check to make a run pass.

### CI without the production private signing key

CI can generate a temporary signing key outside the checkout, compile the target
source for test classpath definitions, and re-sign a copy of the published
production APK with that temporary key. Before using the copy, compare the
complete ZIP member set and bytes against the production artifact, excluding
only v1 signature metadata (`META-INF/MANIFEST.MF` and the corresponding
`.SF`/`.RSA`/`.EC`/`.DSA` signature files). DEX, manifest, resources, assets and any
other `META-INF` files must remain identical. APK v2/v3 signing blocks are outside
the ZIP entries and are expected to change during re-signing.

The disposable target uses v2/v3 signing with v1 disabled. With SDK 35,
re-adding v1 ZIP members while re-signing can retain old signing-block alignment
as an interior ZIP gap. The production scanner correctly leaves that unsupported
layout incomplete. The test must not relax its ZIP checks to hide the gap.
The exact original public release APK is also packaged as a test asset and its
direct-entry scan must complete on the Android runtime.

Pass the re-signed APK as `--app-apk` and the temporary key to this helper; it will
bind the runtime assertions to that copy's SHA-256 and verify that both test
and target certificates match. Use the re-signed target hash in the log checker.
This exercises the production DEX/resources/assets on Android while keeping
the production signing key and a production-signed instrumentation APK out of
CI/public downloads. After instrumentation succeeds, `run_ci.sh` removes only
the disposable test apps, installs the exact production-signed APK and checks
that its launcher starts. This does not test an upgrade from an older installed
release; v1.2.0 has a different signing key and requires a fresh installation.

The final output contains one-line `REFURBCHECK_SMOKE={...}` JSON and a Bundle
`summary` field. Success is `passed: true` and `INSTRUMENTATION_CODE: 0`;
failure is `passed: false`, a failing assertion/trace, and code 1. Parse the final
JSON in CI: `am instrument`'s shell exit status alone is not a test verdict.
The `-r` option is required: stream-formatted output can omit the final raw
instrumentation result code even when the JSON verdict was printed.
The included log checker also binds the result to the expected API, target APK
SHA-256, completed assertion list and conservative assurance flags. Use `--api 36`
on the API 36 emulator.

## Checks and boundaries

- Installed target APK hash must match the exact artifact used by the build
  helper. Live signer, history, installer, package-source and update-owner API
  branches are exercised on the actual emulator runtime.
- Management collection preserves incomplete/unsupported values. Factory-reset
  and capability policies exclude the scanner and never authorize deletion.
- The bundled catalog is loaded, then the signed reference bundle is imported
  into a unique test cache directory. A second bundle has a deliberately changed
  RSA signature with correct ZIP checksums. Rejection must retain the original
  active catalog identity and bytes. Separate preference names preserve the
  app's real update state. Test files/preferences are cleaned up afterward.
- `ApkInspection` hashes, verifies and checks only the installed scanner APK
  using the isolated signed catalog. Its result cannot authorize self-removal.
  Every direct-entry malware scan must finish without skipped entries. A second
  scan checks the exact original release APK bytes, including its original
  signature metadata. The report explicitly does not claim that the phone
  inventory is complete.
- Upstream benign ECDSA, changed-content, v3.1 rotation and stripped-block APK
  fixtures exercise Android's actual cryptographic providers and the API 26/36
  verifier models. Fixtures are copied to test cache, never installed or run.
- Official public factory/RKP certificate fixtures exercise the Android PKIX
  provider. The live guarded attestation probe may return `UNKNOWN` on an
  emulator; success does not require pretending that emulator keys are hardware
  attestations. The external-verification limitation must always remain.

This does **not** measure malware detection accuracy, validate Samsung firmware,
certify physical hardware, exercise every One UI variant, perform an uninstallation
or demonstrate a hardware attestation success on a real Galaxy. Those results
must be reported separately when actually tested.
