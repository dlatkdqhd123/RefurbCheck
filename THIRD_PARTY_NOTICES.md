# Third-party materials

RefurbCheck application code is an independent implementation. RootBeer, Key Attestation, Auditor, App Manager and Hypatia were researched as references; their application code and binary assets are not included.

## Google Android attestation public roots

`app/src/main/assets/google_attestation_roots.pem` contains the two public certificate trust anchors returned by https://android.googleapis.com/attestation/root and documented by https://developer.android.com/privacy-and-security/security-key-attestation. These are public verification materials, not private signing keys. The offline root set does not provide current revocation information. Fetch date and fingerprints are in `docs/attestation.md`.

## Gradle Wrapper

`gradlew`, `gradlew.bat` and `gradle/wrapper/gradle-wrapper.jar` are unmodified distribution files from the Gradle v8.11.1 source repository: https://github.com/gradle/gradle/tree/v8.11.1 . Copyright Gradle contributors, Apache License 2.0. License text: `licenses/Apache-2.0.txt`. The distribution URL and SHA-256 are configured in the wrapper properties.

## Host tests

The test runner downloads JSON-java version 20240303 from Maven Central and verifies a pinned SHA-256 before running tests. Upstream: https://github.com/stleary/JSON-java . Its jar is not distributed in the source archive or application. Android's built-in `org.json` is used in the APK.

Test PEM files are artificial certificates for negative validation tests; they do not contain private keys or live device identities.

## AOSP apksig Android16 QPR2 (included runtime Java code)

`app/libs/apksig-aosp-16.jar` is built from AOSP `platform/tools/apksig` commit
`ba8f1f1c74b62b8742c9946b09d4a9c6ac7446ae` (`android16-qpr2-release`, commit date 2025-07-16;
retrieved 2026-11-07). It is **not** described as code written in November 2026.
Apache-2.0. All 126 included Java sources are unchanged; cloud-only AWS/GCP signing
providers are excluded. The app requires Android API26 and uses its bounded random-access
adapter. Upstream is primarily a desktop library; Android runtime smoke tests and
remaining limits are recorded in the versioned validation report.

- JAR SHA-256: `83d7d7fec92ca21214d180e232a4594d2a1b6ee3b186a7b8ebf338d95e317040`
- Full pinned source and upstream LICENSE: `third_party/apksig/aosp-android16-source.zip`
- Provenance/fixture hashes: `app/libs/apksig-aosp-16.PROVENANCE.json`
- Reproducible build: `python3 tools/build_apksig_port.py`
- Upstream: https://android.googlesource.com/platform/tools/apksig/+/ba8f1f1c74b62b8742c9946b09d4a9c6ac7446ae/

The benign APK fixtures under `tests/apksig-fixtures` are copied from that same AOSP
commit for signature/rotation/stripping regression tests, not malware efficacy tests.
The Android keyattestation v0.4 certificate test fixtures and license are described
in `tests/attestation-fixtures/README-v1.3.md`; no attestation private keys are shipped.

## Public MVT file indicators (included data)

`app/src/main/assets/ioc_sha256.txt` contains 131 BTMOB and 25 EagleMsgSpy public SHA-256 records from https://github.com/mvt-project/mvt-indicators at pinned commit `b22ddf05e1a31e7732b8895676987c5c3482ef65` (2026-08-27). The MIT license is preserved in `licenses/MVT-indicators-MIT.txt` and `app/src/main/assets/ioc_MIT_LICENSE.txt`. Transformation/source-file hashes and pinned URLs are recorded in `ioc_provenance.json`. No malware binary is included. Matching these public file hashes is not broad malware detection.

## Google Android attestation status snapshot (included reference data)

`app/src/main/assets/attestation_revocations.json` is the public JSON response from https://android.googleapis.com/attestation/status collected on 2026-11-06. `attestation_revocations_meta.json` preserves the source URL, collection timestamp, response cache lifetime, record count and SHA-256. It is a dated reference snapshot, not a current online check or a guarantee of non-revocation.

## Commercial documents (research only)

Public Samsung Knox, Phonecheck, Blancco, iVerify, Zimperium and Lookout documentation was used for methodology research. No proprietary engine, SDK, commercial report template or licensed service is bundled. Source links, applicability and limitations are in `docs/commercial-methodology-v1.1.md`.


## Offline antivirus reference data in 1.2.0 (independent data files)

The original bounded exact-hash scanner is independently written MIT code. It is not libclamav, ESET's proprietary engine, Hypatia's application or a copied YARA/ML engine. The following separately licensed data are distributed as separate TSV files; runtime lookup federates the sources. Their corresponding selected source records, transformations, notices and licenses are in `data/antivirus/`, and runtime notices are in `app/src/main/assets/antivirus_licenses/`.

| Asset | Records | License and source |
|---|---:|---|
| `malware_clamav.tsv` | 13,764 | ClamAV/Cisco Talos, GPL-2.0-only; selected Android HDB/HSB data from main CVD 63 with daily 28175 retirement rules |
| `malware_clamav_allow.tsv` | 996 allow rules | ClamAV/Cisco Talos, GPL-2.0-only; scope restricted to ClamAV evidence |
| `malware_eset.tsv` | 131 | ESET malware-ioc, BSD-2-Clause, commit 825b826c5cbffcc1e59c16581ffdf7d527e8b695 |
| `malware_echap.tsv` | 1,594 | Échap stalkerware-indicators, CC BY 4.0, commit 426156175adc84af7fbdd41486c046f9ecb40436 |
| `malware_mvt.tsv` | 156 | MVT indicators, MIT; separately normalized from the original pinned MVT asset listed above |

Changes: platform selection, strict file-hash/size normalization, removed retired/duplicate/unsupported categories, per-source splitting and a fixed index. No malware binaries are distributed. Original source-license declarations and attribution remain in the corresponding data folders. The application does not claim upstream endorsement or equivalent detection performance. See `docs/antivirus.md` for sources, snapshot ages and verification limits.
