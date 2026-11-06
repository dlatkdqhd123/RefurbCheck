#!/usr/bin/env python3
"""Rebuild the pinned Android-focused supplemental hash indicators.

This processes text indicators only. It does not download or execute samples.
Requires Python 3.9+ and PyYAML 6.x. Default operation is entirely offline.
"""

import argparse
import collections
import csv
import hashlib
import io
import json
import re
from pathlib import Path
from urllib.request import Request, urlopen

import yaml


ESET_FAMILIES = (
    "aridspy", "callphantom", "evilvideo", "ghostchat", "gravityrat", "gref",
    "kamran", "ngate", "promptspy", "prospytospy", "spyloan", "vajraspy",
)
HEX64 = re.compile(r"[0-9A-Fa-f]{64}")
CERT40 = re.compile(r"[0-9A-Fa-f]{40}")
ANDROID_PACKAGE = re.compile(r"[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)+")
POST_RESET_REMOVAL_POLICY_ID = "post-reset-user-confirmed-removal-v1"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def safe_name(name):
    value = re.sub(r"[^A-Za-z0-9._-]", "_", name)
    if not value or len(value) > 120:
        raise ValueError("Unexpected source name")
    return value


def prepare_inputs(root, manifest, download):
    files = {}
    for item in manifest["files"]:
        relative = Path(item["path"])
        if relative.is_absolute() or ".." in relative.parts or relative.parts[0] != "raw":
            raise ValueError("Unexpected input path")
        target = root / relative
        if download:
            # Every allowed URL is a fixed upstream repository/commit path.
            expected_prefix = "https://raw.githubusercontent.com/" + item["sourceRepository"] + "/" + item["sourceCommit"] + "/"
            if item["sourceUrl"] != expected_prefix + item["repositoryPath"]:
                raise ValueError("Unpinned source URL")
            request = Request(item["sourceUrl"], headers={"User-Agent": "RefurbCheck-source-builder/1.2"})
            with urlopen(request, timeout=30) as response:
                data = response.read(item["sizeBytes"] + 1)
            if len(data) != item["sizeBytes"] or sha256(data) != item["sha256"]:
                raise ValueError("Downloaded source integrity mismatch: " + str(relative))
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
        data = target.read_bytes()
        if len(data) != item["sizeBytes"] or sha256(data) != item["sha256"]:
            raise ValueError("Local source integrity mismatch: " + str(relative))
        files[relative.as_posix()] = data.decode("utf-8", "strict")
    return files


def build_eset(files):
    rows = []
    evidence = []
    counts = {}
    for family in ESET_FAMILIES:
        readme = files[f"raw/eset/{family}/README.adoc"]
        if "android" not in readme.lower():
            raise ValueError("Selected ESET source no longer establishes Android context")
        hashes = files[f"raw/eset/{family}/samples.sha256"].splitlines()
        if not hashes:
            raise ValueError("Empty ESET source: " + family)
        counts[family] = 0
        for line_number, digest in enumerate(hashes, 1):
            digest = digest.strip().lower()
            if not HEX64.fullmatch(digest):
                raise ValueError("Invalid ESET SHA-256: " + family)
            rows.append(("sha256", digest, "*", "Android.ESET." + family, "eset.android"))
            evidence.append({"sourceId": "eset.android", "sha256": digest,
                             "sourcePath": f"raw/eset/{family}/samples.sha256", "sourceLine": line_number,
                             "family": family, "selectionEvidence": f"raw/eset/{family}/README.adoc"})
            counts[family] += 1
    return rows, evidence, counts


def build_echap(files):
    aliases = {}
    for filename, category in (("ioc.yaml", "stalkerware"), ("watchware.yaml", "watchware")):
        entries = yaml.safe_load(files["raw/echap/" + filename])
        if not isinstance(entries, list):
            raise ValueError("Invalid Echap classification list")
        for entry in entries:
            if entry.get("type") != category or not isinstance(entry.get("name"), str):
                raise ValueError("Unexpected Echap category")
            for name in {entry["name"], *entry.get("names", [])}:
                if not isinstance(name, str):
                    raise ValueError("Invalid Echap name")
                value = {"category": category, "canonicalName": entry["name"], "classificationPath": filename}
                candidates = aliases.setdefault(name, [])
                if value not in candidates:
                    candidates.append(value)
    rows, evidence, exclusions = [], [], []
    stats = collections.Counter()
    seen = set()
    reader = csv.DictReader(io.StringIO(files["raw/echap/samples.csv"], newline=""))
    if reader.fieldnames != ["SHA256", "Package Name", "Certificate", "Version", "App"]:
        raise ValueError("Unexpected Echap CSV columns")
    for line_number, row in enumerate(reader, 2):
        stats["sourceRows"] += 1
        if None in row or any(value is None for value in row.values()):
            raise ValueError("Malformed Echap CSV row")
        digest = row["SHA256"].strip().lower()
        if not HEX64.fullmatch(digest) or digest in seen:
            raise ValueError("Invalid or duplicate Echap SHA-256")
        seen.add(digest)
        candidates = aliases.get(row["App"])
        if not candidates:
            raise ValueError("Unclassified Echap sample")
        categories = {item["category"] for item in candidates}
        if len(categories) != 1:
            stats["excludedAmbiguousCategory"] += 1
            exclusions.append({"sha256": digest, "sourceLine": line_number,
                               "app": row["App"], "reason": "Conflicting stalkerware/watchware classification"})
            continue
        category = next(iter(categories))
        stats["sourceRows." + category] += 1
        package, certificate = row["Package Name"].strip(), row["Certificate"].strip()
        # README covers both Android and iOS. Include only rows with Android
        # package syntax and the APK signing-certificate SHA-1 metadata.
        # The certificate is source-selection evidence, never a malware rule.
        if not ANDROID_PACKAGE.fullmatch(package) or not CERT40.fullmatch(certificate):
            stats["excludedMissingOrInvalidAndroidMetadata"] += 1
            stats["excludedMissingOrInvalidAndroidMetadata." + category] += 1
            exclusions.append({"sha256": digest, "sourceLine": line_number,
                               "app": row["App"], "reason": "Android package and signing-certificate metadata are not both available"})
            continue
        source_id = "echap." + category
        rows.append(("sha256", digest, "*", "Echap." + category + "." + safe_name(row["App"]), source_id))
        evidence.append({"sourceId": source_id, "sha256": digest, "sourcePath": "raw/echap/samples.csv",
                         "sourceLine": line_number, "upstreamName": row["App"],
                         "canonicalNames": sorted({item["canonicalName"] for item in candidates}),
                         "classificationPath": "raw/echap/" + ("ioc.yaml" if category == "stalkerware" else "watchware.yaml"),
                         "upstreamCategory": category, "packageName": package,
                         "certificateSha1": certificate.lower(), "version": row["Version"],
                         "referenceClassification": "MONITORING_REFERENCE",
                         "removalPolicyRef": POST_RESET_REMOVAL_POLICY_ID,
                         "silentRemoval": False, "systemApprovalRequired": True})
        stats["selectedRows"] += 1
        stats[category] += 1
    return rows, evidence, exclusions, dict(stats)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=Path(__file__).resolve().parent)
    parser.add_argument("--download", action="store_true", help="Re-fetch only pinned text sources, checking size and SHA-256 before writing")
    args = parser.parse_args()
    root = args.root.resolve()
    manifest_bytes = (root / "source-manifest.json").read_bytes()
    manifest = json.loads(manifest_bytes)
    if manifest.get("schema") != "refurbcheck-supplemental-source-manifest-v1":
        raise ValueError("Unknown source manifest")
    files = prepare_inputs(root, manifest, args.download)
    erows, eevidence, ecounts = build_eset(files)
    srows, sevidence, exclusions, scounts = build_echap(files)
    rows = sorted(set(erows + srows))
    payload = "".join("\t".join(row) + "\n" for row in rows).encode("utf-8")
    output = root / "normalized"
    output.mkdir(parents=True, exist_ok=True)
    (output / "supplemental.tsv").write_bytes(payload)
    provenance = {
        "schema": "refurbcheck-supplemental-provenance-v1",
        "sourceManifestSha256": sha256(manifest_bytes),
        "retrievedAtUtc": manifest["retrievedAtUtc"],
        "output": {"path": "supplemental.tsv", "sha256": sha256(payload), "sizeBytes": len(payload),
                   "rowCount": len(rows), "uniqueSha256Count": len({row[1] for row in rows}),
                   "format": "algorithm<TAB>digest<TAB>size-or-*<TAB>name<TAB>sourceId; no header"},
        "sources": [
            {"sourceId": "eset.android", "sourceType": "android-campaign-malware-ioc", "license": "BSD-2-Clause",
             "repository": "https://github.com/eset/malware-ioc", "commit": "825b826c5cbffcc1e59c16581ffdf7d527e8b695",
             "scope": "SHA-256 sample lists from 12 explicitly selected Android-campaign folders; no full ESET antivirus engine or database",
             "familyCounts": ecounts, "rowCount": len(erows), "hashesMayDescribeEmbeddedPayloads": True,
             "knownFileSizesAvailable": False},
            {"sourceId": "echap.stalkerware", "sourceType": "stalkerware-monitoring-indicator", "license": "CC-BY-4.0",
             "repository": "https://github.com/AssoEchap/stalkerware-indicators", "commit": "426156175adc84af7fbdd41486c046f9ecb40436",
             "scope": "Echap samples with Android package and certificate metadata, explicitly classified as stalkerware by ioc.yaml",
             "rowCount": scounts.get("stalkerware", 0), "referenceClassification": "MONITORING_REFERENCE",
             "removalPolicyRef": POST_RESET_REMOVAL_POLICY_ID,
             "silentRemoval": False, "systemApprovalRequired": True,
             "interpretation": "Exact match to a published surveillance-app sample, not proof of non-consensual monitoring. The user's post-reset preference can make a matching ordinary app a removal candidate after live preflight; Android user approval remains mandatory."},
            {"sourceId": "echap.watchware", "sourceType": "dual-use-monitoring-indicator", "license": "CC-BY-4.0",
             "repository": "https://github.com/AssoEchap/stalkerware-indicators", "commit": "426156175adc84af7fbdd41486c046f9ecb40436",
             "scope": "Echap samples with Android package and certificate metadata, explicitly classified as watchware by watchware.yaml",
             "rowCount": scounts.get("watchware", 0), "referenceClassification": "MONITORING_REFERENCE",
             "removalPolicyRef": POST_RESET_REMOVAL_POLICY_ID,
             "silentRemoval": False, "systemApprovalRequired": True,
             "interpretation": "Monitoring or parental-control software may be intentional and legitimate. A post-reset removal preference does not upgrade this category to confirmed malware; live preflight and Android user approval remain mandatory."},
        ],
        "removalPolicy": {
            "id": POST_RESET_REMOVAL_POLICY_ID,
            "mode": "post-reset",
            "defaultEnabled": True,
            "userExpectation": "The user runs RefurbCheck immediately after factory reset and expects no intentionally installed monitoring or management app.",
            "automaticSteps": "Scan installed APKs, select eligible reference matches, revalidate the live target, then request Android's uninstall confirmation.",
            "silentRemoval": False,
            "systemApprovalRequired": True,
            "datasetRecordAloneAuthorizesRemoval": False,
            "requirements": [
                "Use only the current in-memory scan inventory; imported reports and these provenance records cannot drive removal.",
                "Exclude system apps, updated system apps and RefurbCheck itself.",
                "Require complete, stable exact file evidence bound to the matched APK's SHA-256; a monitoring reference retains its monitoring classification.",
                "Immediately before confirmation, reload the pinned shipping catalog and reproduce the exact source, signature, digest, size and whole-APK or entry identity.",
                "Recheck the target APK on one file descriptor, its file stamps and hashes, plus the package version, update time and full base/split path set.",
                "Block on cancellation, resource limits, incomplete archive scanning, database errors, changed evidence, active target administrator privileges or unreadable administrator state.",
                "Android's confirmation and the user's approval are required for deletion; requesting the dialog is not a completed-removal claim.",
            ],
            "monitoringInterpretation": "This is the user's installation preference after reset, not evidence that monitoring occurred without consent or that every monitoring tool is malicious.",
        },
        "echapSelection": scounts,
        "transformations": ["Verified pinned input bytes", "Parsed exact SHA-256 sample indicators only", "Lowercased digests", "Kept unknown sizes as *", "Excluded Echap samples lacking Android package/certificate metadata", "Preserved Echap stalkerware/watchware categories", "Excluded unselected ESET platform/campaign folders", "Sorted and deduplicated exact TSV records"],
        "limitations": ["Hash matches detect unchanged known files only", "No-match does not establish absence of malware", "No malware binaries downloaded or analysed", "No certificate-only or package-name-only malware rules", "Source publication date does not mean every sample is newly discovered", "Input source commits are pinned but not asserted to be publisher-signed"],
    }
    for filename, value in (("provenance.json", provenance), ("selected-evidence.json", eevidence + sevidence), ("excluded-echap.json", exclusions)):
        (output / filename).write_text(json.dumps(value, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"output": provenance["output"], "esetCounts": ecounts, "echapSelection": scounts}, ensure_ascii=False))


if __name__ == "__main__":
    main()
