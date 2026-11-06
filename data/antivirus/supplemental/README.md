# RefurbCheck Android-focused supplemental indicators

This directory contains **text indicators and research documentation only**. No malware APK, DEX, executable, or other sample binary was downloaded. The data supplements an on-device scanner; it does not include the ESET antivirus engine, a full ESET database, or a complete stalkerware detector.

## Rebuild

Use Python 3.9 or later with PyYAML 6.x:

```sh
python3 build_supplemental.py
```

The default build is offline. It checks the size and SHA-256 of every source against `source-manifest.json`, parses only selected sources, and writes `normalized/`. To retrieve those same pinned text files again, use `python3 build_supplemental.py --download`; downloaded bytes must match the expected size and SHA-256 before a local source is replaced.

The output `normalized/supplemental.tsv` has five fields, without a header:

```text
algorithm<TAB>digest<TAB>size-or-*<TAB>name<TAB>sourceId
```

Only SHA-256 is emitted here. All sizes are `*` because these sources do not publish a reliable file size for each selected hash. A wildcard means size is unknown, never that zero-length content has been verified. Records are sorted and exact duplicate records are removed. `selected-evidence.json` maps each selected digest back to its source line and classification; `excluded-echap.json` records excluded rows and reasons.

## Sources and scope

### ESET

- Repository: <https://github.com/eset/malware-ioc>
- Pinned commit: `825b826c5cbffcc1e59c16581ffdf7d527e8b695`, upstream commit time `2026-11-04T20:10:43Z`.
- License: **BSD-2-Clause**; the complete original copyright notice and conditions are in `raw/eset/LICENSE`.
- Selected folders: `aridspy`, `callphantom`, `evilvideo`, `ghostchat`, `gravityrat`, `gref`, `kamran`, `ngate`, `promptspy`, `prospytospy`, `spyloan`, `vajraspy`.
- Each selected folder's README explicitly describes an Android threat or campaign. Only that folder's `samples.sha256` is included; Windows and other unselected campaigns are excluded. Mixed-platform `hamkombat` was not selected.
- There are **131** unique selected SHA-256 indicators across these 12 campaigns. They may describe an APK or a campaign payload; do not claim every digest identifies a complete APK. The scanning result should disclose whether a match was against the whole APK or an embedded file.
- Source identifier: `eset.android`.

### Échap

- Repository: <https://github.com/AssoEchap/stalkerware-indicators>
- Pinned commit: `426156175adc84af7fbdd41486c046f9ecb40436`, upstream commit time `2026-10-20T19:19:33Z`.
- License: **Creative Commons Attribution 4.0 International (CC BY 4.0)**, as stated in the upstream README. License: <https://creativecommons.org/licenses/by/4.0/>. Complete legal text: `licenses/CC-BY-4.0.txt`.
- Attribution: Échap's Stalkerware Indicators of Compromise project, maintained by Julien Voisin and Tek, and its contributors. The original README is retained in `raw/echap/README.md`.
- Changes made here: selected rows with an Android-shaped package name and an APK signing-certificate SHA-1 field, classified names using `ioc.yaml` and `watchware.yaml`, normalized digests and names, excluded incomplete Android metadata, sorted records, and produced the five-column TSV and provenance records.
- The original source contains **3,228** sample hashes and covers Android and iOS. This build selects **1,594** hashes with the Android package/certificate metadata and excludes **1,634** rows missing it. Package/certificate metadata is used to constrain the source selection; it is **not** used as a certificate-only or package-name-only malware detection rule.
- All 3,228 rows of the current sample CSV map to the upstream **stalkerware** classification. The **watchware** class is kept separate in the builder and provenance, but there are no watchware sample rows in this pinned CSV. Its YAML classification list contains watchware applications without corresponding sample hashes here. The code never treats a watchware indicator as confirmed malware.
- Source identifiers: `echap.stalkerware`, and `echap.watchware` if a future explicitly reviewed input produces eligible rows.

**An Échap match identifies a published monitoring-tool reference.** It does not establish that the device is currently being monitored without consent. Monitoring and parental-control tools can be intentionally installed. The upstream stalkerware/watchware category is retained, and the app reports both as `MONITORING_REFERENCE` rather than upgrading them to confirmed malware.

## Post-reset removal policy

The user intends to run this app immediately after a factory reset and has stated that no monitoring or management app will have been intentionally installed. The default post-reset mode therefore includes an ordinary app with an exact Échap reference match among the candidates for immediate removal review. This is the user's installation preference, not a stronger conclusion about maliciousness or consent.

The automatic sequence is **scan → validate the current target again → open Android's uninstall confirmation**. A database row or an imported report does not itself authorize removal. The app uses the current in-memory inventory, excludes system apps, updated system apps and itself, and reloads its pinned catalog immediately before the confirmation request. It rechecks the exact reference identity, complete target-file scan, stable APK fingerprint, package version and full base/split path set. Incomplete archive scanning, cancellation, resource limits, database errors, changed files or package metadata, and active or unreadable target administrator status block this automatic sequence. Active administrator privileges must first be disabled through Android settings.

Deletion still requires the user's approval in Android's system dialog. The generated evidence and provenance use `silentRemoval: false`, `systemApprovalRequired: true` and a `removalPolicyRef` referring to `post-reset-user-confirmed-removal-v1`; they do not store an unconditional per-signature removal-eligibility flag. The policy requirements are recorded in `normalized/provenance.json`. Opening the confirmation dialog is not a claim that the app was deleted or the phone was fully restored. The main app checks the outcome and scans again after the user returns.

The unchanged attribution statement that removal authorization does not come from the indicators remains applicable: the installation preference comes from the user, and the final approval comes from Android's confirmation dialog.

## Integration requirements

1. Keep each record's `sourceId` through matching, reporting, and remediation.
2. Keep whole-APK matches separate from embedded-file matches. No hash match or scan coverage statement should imply that the malware executed.
3. An absent match means only that a scanned file did not match these known indicators. This list has no general behavioural or machine-learning detector.
4. Verify the scanner's actual file identity/stability and complete hashing before using a hash match as evidence. Cancelled, changed, unreadable, or partially scanned files remain incomplete.
5. Pinned commit IDs and input hashes establish reproducible bytes fetched over HTTPS. They are not a claim that the source Git commits carry publisher signatures, or that all indicators are guaranteed correct.
6. The source commit date does not mean every indicator was discovered recently. Some campaigns and samples are older. Dataset freshness and detector coverage are separate properties.
7. No endorsement or affiliation with ESET, Échap, Google, Samsung, Cisco, or ClamAV is implied.
8. Keep source classification separate from removal policy. Monitoring-reference matches can be removal candidates in the user's post-reset mode without asserting covert monitoring or converting them to confirmed malware. Always run the live preflight and require Android approval.

## Snapshot output

- Rows / unique SHA-256 indicators: **1,725 / 1,725**.
- Bytes: **209,210**.
- SHA-256: `54e7ce9a39e48e8765e417ac5c422e5fb32bd05c956cd384ede193aa0e2b7734`.
- All input byte hashes, upstream URLs, fixed commits, and the retrieval timestamp are in `source-manifest.json`.
- Source types, selection counts, output hash, and limitations are in `normalized/provenance.json`.

