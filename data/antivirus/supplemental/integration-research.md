# Free antivirus integration options reviewed on 2026-11-06

## Recommended scope

For a free, sideloaded APK without an account or backend, use a clearly bounded local signature detector with authentic, pinned sources, whole-APK and embedded-file evidence, explicit coverage limits, and reviewed remediation. A larger database alone does not add behavioural analysis, emulation, cloud reputation, or all of a commercial antivirus engine's detection capabilities.

The ESET and Echap text indicators prepared in this directory are a small, Android-focused supplement. The primary ClamAV data acquisition and verification are handled separately. If only selected ClamAV signature formats are implemented, name the supported formats and omitted formats explicitly rather than claiming the full ClamAV engine is embedded.

## Implemented post-reset remediation policy

The user clarified that the phone will be checked immediately after a factory reset and that no monitoring or management app will have been intentionally installed. In the default post-reset mode, an exact bundled reference match in an ordinary installed app can therefore start the removal sequence automatically: validate the current target again, then request Android's uninstall confirmation. The user must approve deletion in that system dialog. The app does not silently uninstall packages.

This includes Échap monitoring references under the user's installation preference. It does not establish non-consensual monitoring, malicious execution, or that a parental-control tool is inherently malicious. The upstream stalkerware/watchware categories remain distinct, and the application classification remains `MONITORING_REFERENCE`.

Eligibility comes from the current in-memory scan and the live Android preflight, not a source label, permission pattern, imported report, or provenance field. The preflight reloads the pinned catalog, reproduces the exact match, verifies complete target-file scanning and a stable outer APK SHA-256, and checks package version and the whole base/split path set before and after verification. System apps, updated system apps and the checker itself are excluded. Cancellation, limits, incomplete archive inspection, database failure, changed target evidence, or active/unreadable administrator status stop the automatic sequence. Opening a system confirmation is not proof that removal completed; the app checks again after the user returns.

`normalized/provenance.json` records this as `post-reset-user-confirmed-removal-v1`, with `silentRemoval: false` and `systemApprovalRequired: true`. The text references below concern the integration options reviewed; handing off to another antivirus product still does not establish that its scan ran or passed.

## Samsung App protection

Samsung documents Device care → App protection → Scan phone. The Galaxy Store listing also describes installation-time and daily scans. These are useful on a Galaxy device, but the reviewed public Samsung documents do not expose an ordinary third-party app API for starting the same scan and reading its result. Opening Device care is a user action handoff, not evidence that a scan ran or passed. The existing fallback/settings flow should retain that distinction.

- Samsung Korea guidance: <https://www.samsungsvc.co.kr/solution/618789>
- Official Galaxy Store package listing: <https://galaxystore.samsung.com/detail/com.samsung.android.sm.devicesecurity>
- Samsung guidance on the McAfee partnership: <https://www.samsung.com/uk/support/mobile-devices/how-do-i-use-the-smart-manager-application-to-check-for-malware-or-viruses/>

## Google Play Protect / SafetyNet Verify Apps

Google still publishes `isVerifyAppsEnabled()`, `enableVerifyApps()` and `listHarmfulApps()` in the Verify Apps guide, while recommending Play Integrity for Play Protect status. `enableVerifyApps()` requests user consent. `listHarmfulApps()` supplies known potentially harmful apps for the current user/account, including a package name, SHA-256, category, and last scan time. It is not documented as an instruction to perform a new, complete antivirus scan immediately. A successful empty list must not be promoted to a malware-free certificate; API errors, missing Google Play services, denied consent, and stale results require separate states.

The current SafetyNet dependency guide lists `com.google.android.gms:play-services-safetynet:18.1.0`. Its explicit deprecation notice concerns SafetyNet **Attestation** and reCAPTCHA. Firebase App Check's SafetyNet shutdown refers to that attestation provider; it is not by itself proof that every Verify Apps API has shut down. Actual Verify Apps availability on the user's Galaxy remains untested, so no working integration should be promised from the documentation alone.

- <https://developer.android.com/privacy-and-security/safetynet/verify-apps>
- <https://developer.android.com/privacy-and-security/safetynet>
- <https://developers.google.com/android/reference/com/google/android/gms/safetynet/SafetyNetApi.HarmfulAppsResponse>

## VirusTotal

The public API needs a user key and is limited to four requests per minute and 500 per day. Official constraints disallow commercial products/services and business workflows that do not contribute new files. This makes it unsuitable as the default, immediate, keyless full-phone scanning engine. A hash-only lookup retrieves an existing report; it does not scan an unseen APK. It still discloses the queried digest to the service. An optional integration would need explicit user choice, truthful stale/unknown states, and quota handling. No APK should be automatically uploaded as part of this offline app's scan.

- <https://docs.virustotal.com/reference/public-vs-premium-api>
- <https://docs.virustotal.com/reference/getting-started>

## Hypatia

The original Divested-Mobile repository was archived on 2024-12-23. The MaintainTeam fork describes ClamAV-style hash scanning and publishes a database generator. Its default data are serialized Guava Bloom filters. The README acknowledges Bloom-filter false positives; a Bloom hit is not an exact-hash confirmation and should not automatically justify removal. The fork's roadmap still lists third-party scan invocation as a planned item. Its source uses AGPL licensing and its aggregated data sources have differing licenses, so copying the app and attributing everything to one permissive license would be incorrect.

The current generator reads ClamAV `.hdb/.hsb/.hdu/.hsu` files extracted with `sigtool`, plus other sources, then deploys Bloom-filter outputs. The reviewed workflow did not publish the original exact-hash datasets. Use appropriately licensed, authenticated original sources instead of treating that Bloom output as an exact database.

- <https://github.com/Divested-Mobile/Hypatia>
- <https://github.com/MaintainTeam/Hypatia>
- <https://github.com/MaintainTeam/HypatiaDatabases>
- <https://github.com/MaintainTeam/HypatiaDatabases/blob/main/.github/workflows/generate_stable.yml>

## LibreAV

LibreAV uses permissions and intent-filter features for on-device machine-learning predictions. Its own README calls it an educational, early-stage project with potentially many false positives and warns against judging apps from its result alone. The code is GPL-3.0-or-later. An unvalidated permission classifier is not an adequate basis for declaring a phone clean or deleting an app; it is not recommended as this version's primary detector.

- <https://github.com/projectmatris/antimalwareapp>

## Raspirus

The current Raspirus repository describes a rules-based Rust scanner, a major rewrite, and YARA support. Its release history says the old hash-signature database support was dropped. Historical descriptions of a cross-platform hash scanner should not be treated as a current Android library or a current redistributable Android signature feed. No ready Android integration was established in this review.

- <https://github.com/Raspirus/raspirus>
- <https://github.com/Raspirus/raspirus/releases>

## ClamAV official acquisition routes

The ClamAV FAQ recommends FreshClam or CVDUpdate over manual database downloads. The official non-`_base` Docker images include signature databases and are a separately documented distribution route. An official image's database payload can be extracted and independently verified against ClamAV's signature scheme before selecting supported Android indicators. Avoid repeated requests after a refusal and do not substitute an arbitrary unverified mirror. Version 1.5 introduced detached `.cvd.sign` signatures; compatibility with both signature mechanisms must be established if a verifier uses them.

- <https://docs.clamav.net/faq/faq-cvd.html>
- <https://docs.clamav.net/manual/Installing/Docker.html>
- <https://blog.clamav.net/2025/10/clamav-150-released.html>
