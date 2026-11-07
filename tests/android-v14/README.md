# Android v1.4 one-run, security and upgrade runtime tests

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
ANDROID_HOME=/path/to/android-sdk RUNNER_TEMP=/path/to/disposable-temp \
  bash tests/android-v14/run_ci.sh 26

ANDROID_HOME=/path/to/android-sdk RUNNER_TEMP=/path/to/disposable-temp \
  bash tests/android-v14/run_ci.sh 36
```

The SDK build requires platform 35, build tools 35.0.0, JDK 17, platform-tools,
the emulator, command-line tools and the selected `google_apis;x86_64` system
image. The Linux runner needs KVM. `run_ci.sh` creates isolated Android user and
AVD directories, uses explicit SDK executable paths, and cleans up its own
emulator and temporary signing key. It is intended for a disposable runner,
not a connected personal phone. Results are written to `build/runtime-results`.

A future run
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
CI/public downloads. The separate instrumentation APK is signed only with this
temporary key and contains no production classes or endpoints.

After instrumentation succeeds, `run_ci.sh` removes the two disposable test
packages and installs the exact published `release/RefurbCheck-1.3.0.apk`, whose
SHA-256 is pinned in `check_upgrade.py`. It then installs the exact v1.4 APK with
ordinary `adb install -r`, without uninstalling v1.3 in between. Both public APK
signatures must match the established production certificate. Android must
report the version transition from 1.3.0/code 4 to 1.4.0/code 5 and preserve the
original first-install record. Both public launchers must start successfully.

The upgraded original v1.4 APK must expose the one-run screen in its real UI
hierarchy. The job saves `production-one-run.png`, `production-one-run.xml` and
`upgrade-summary.json` for inspection. These are runtime captures, not mockups.
The upgrade check confirms replacement and the installation record; it does
not claim that every possible user preference or stored report was migrated.
v1.2.0 has a different signing key and is outside this in-place upgrade test.

The final output contains one-line `REFURBCHECK_SMOKE={...}` JSON and a Bundle
`summary` field. Success is `passed: true` and `INSTRUMENTATION_CODE: 0`;
failure is `passed: false`, a failing assertion/trace, and code 1. Parse the final
JSON in CI: `am instrument`'s shell exit status alone is not a test verdict.
The `-r` option is required: stream-formatted output can omit the final raw
instrumentation result code even when the JSON verdict was printed.
The included log checker also binds the result to the expected API, target APK
SHA-256, completed assertion list, recorded one-run identities and conservative
assurance flags. Missing lifecycle scenarios or a missing final structured
result fail the job. Emulator boot and instrumentation have bounded deadlines.

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
- The real `MainActivity` opens from a launcher intent and must start a cycle
  without pressing a start button. The actual `자동 점검 중단` button is clicked
  through its Android view. The cycle must immediately become `CANCELLED`, offer
  no automatic removal candidate, and remain cancelled when its worker exits.
- `UiAutomation.setRotation` changes the actual display orientation, and the
  test requires a new Activity object. `Activity.moveTaskToBack` backgrounds
  the app; `ActivityManager.AppTask.moveToFront` resumes the existing task
  without a launcher intent. Rotation and resume must preserve the same cycle,
  including a stopped cycle. No fake lifecycle callback substitutes for these
  Android operations.
- A new `ACTION_MAIN`/`CATEGORY_LAUNCHER` entry after cancellation must create a
  different cycle. That second cycle also rotates and backgrounds/resumes, and
  then runs the actual whole-emulator scan to its final report. With no matching
  removable app, it must complete one initial scan with no redundant rescan,
  no invented removal count, and an explicit update outcome. The exported
  `evidence.oneRun` must contain that same completed cycle.
- Every captured flow and the final report retain false factory-original,
  malware-absence and physical-hardware assurance flags. Workflow completion
  must never change these domains to verified. No fake malware eligibility or
  deletion authorization is inserted. Transitions for uninstall outcomes and
  after-removal rescans are checked separately in state/policy tests. Actual
  uninstall interaction remains unclaimed as a real-runtime outcome here.
- A bounded worker barrier queues a manual catalog update, then the real Stop
  button cancels it before the worker is released. The operation must receive
  its own cancellation token. Its production budget check rejects cancellation
  before opening a network connection; the delayed completion callback must
  clear busy state while preserving the cancelled cycle, report and scan count.

The lifecycle exercise uses official Android APIs:
[UiAutomation rotation](https://developer.android.com/reference/android/app/UiAutomation#setRotation(int)),
[AppTask resumption](https://developer.android.com/reference/android/app/ActivityManager.AppTask#moveToFront()).

This does **not** measure malware detection accuracy, validate Samsung firmware,
certify physical hardware, exercise every One UI variant, perform an uninstallation
or demonstrate a hardware attestation success on a real Galaxy. Those results
must be reported separately when actually tested.
