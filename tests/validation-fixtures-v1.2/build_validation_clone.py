#!/usr/bin/env python3
"""Create/build a separate testOnly clone after the production owner freezes.

This does not modify the production tree. Behavior-bearing Java source must
remain byte-identical except for the generated, explicitly synthetic catalog.
"""
from datetime import datetime, timezone
from pathlib import Path
import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
PRODUCTION = ROOT.parent.parent / "refurbcheck"
CLONE = ROOT / "validation-source"
PACKAGE = "io.github.refurbcheck.validation"
ANDROID = "{http://schemas.android.com/apk/res/android}"


def sha(data):
    return hashlib.sha256(data).hexdigest()


def encoded(value):
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")


def java_array(values):
    return "new String[]{" + ",".join(json.dumps(value) for value in values) + "}"


def fingerprint(root):
    return {str(p.relative_to(root)): sha(p.read_bytes())
            for p in sorted((root / "app/src/main").rglob("*")) if p.is_file()}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--freeze-confirmed", action="store_true")
    args = parser.parse_args()
    if not args.freeze_confirmed:
        parser.error("Run only after the owner reports a source freeze")
    if CLONE.exists():
        parser.error("Refusing to overwrite an existing validation clone")
    source_before = fingerprint(PRODUCTION)
    shutil.copytree(PRODUCTION, CLONE, ignore=shutil.ignore_patterns(
        ".git", "build", "dist", "release", "__pycache__", ".gradle"))
    if fingerprint(CLONE) != source_before or fingerprint(PRODUCTION) != source_before:
        raise RuntimeError("Source changed during freeze snapshot")
    main_source = CLONE / "app/src/main"
    manifest = main_source / "AndroidManifest.xml"
    ET.register_namespace("android", "http://schemas.android.com/apk/res/android")
    tree = ET.parse(manifest)
    tree.getroot().set("package", PACKAGE)
    application = tree.getroot().find("application")
    application.set(ANDROID + "label", "RefurbCheck Validation ONLY")
    application.set(ANDROID + "testOnly", "true")
    application.set(ANDROID + "debuggable", "true")
    activities = application.findall("activity")
    if len(activities) != 1 or activities[0].get(ANDROID + "name") not in {
            ".MainActivity", "io.github.refurbcheck.MainActivity"}:
        raise RuntimeError("Unexpected activity declaration")
    activities[0].set(ANDROID + "name", "io.github.refurbcheck.MainActivity")
    tree.write(manifest, encoding="utf-8", xml_declaration=True)

    assets = main_source / "assets"
    fixture_report = json.loads((ROOT / "fixtures.json").read_text())
    fixture_bytes = (ROOT / "synthetic-only.tsv").read_bytes()
    if sha(fixture_bytes) != fixture_report["syntheticDatasetSha256"]:
        raise RuntimeError("Synthetic data pin mismatch")
    fixture_name = "malware_fixture.tsv"
    for old in ("malware_clamav.tsv", "malware_eset.tsv", "malware_echap.tsv", "malware_mvt.tsv"):
        (assets / old).unlink()
    (assets / fixture_name).write_bytes(fixture_bytes)
    allow_name = "malware_clamav_allow.tsv"
    allow_bytes = (assets / allow_name).read_bytes()
    allow_count = len([line for line in allow_bytes.splitlines() if line and not line.startswith(b"#")])
    index = [{"asset": fixture_name, "sha256": sha(fixture_bytes)},
             {"asset": allow_name, "sha256": sha(allow_bytes)}]
    catalog_digest = sha(json.dumps(index, ensure_ascii=True, separators=(",", ":")).encode("ascii"))
    now = datetime.now(timezone.utc)
    meta = {
        "schema": "refurbcheck-malware-catalog-v1", "snapshotDate": now.date().isoformat(),
        "retrievedAtEpochMillis": int(now.timestamp() * 1000),
        "catalogDigest": catalog_digest, "catalogIndex": index,
        "entryCount": 2, "countsBySource": {"fixture.synthetic": 2},
        "testOnly": True, "realMalwareSamplesUsed": False,
        "purpose": "Benign emulator-only synthetic reference hashes; not shipping antivirus data",
        "fixtures": fixture_report["fixtures"],
        "allowlistNote": "Unmodified official Clam source-only allowlist; does not suppress fixture.synthetic",
        "legacyIocNote": "Unmodified legacy MVT IOC path remains present; no fixture is in that dataset",
    }
    meta_bytes = encoded(meta)
    (assets / "malware_catalog.json").write_bytes(meta_bytes)
    java = "package io.github.refurbcheck;\n\n/** TEST ONLY: benign synthetic fixture hashes. */\nfinal class MalwareCatalog {\n    private MalwareCatalog() { }\n"
    for name, value in (("DATA_SHA256", catalog_digest), ("METADATA_SHA256", sha(meta_bytes)),
                        ("SNAPSHOT_DATE", now.date().isoformat()), ("ALLOW_SHA256", sha(allow_bytes))):
        java += "    static final String " + name + "=" + json.dumps(value) + ";\n"
    java += "    static final int ENTRY_COUNT=2, ALLOW_ENTRY_COUNT=" + str(allow_count) + ";\n"
    java += "    static final String[] SOURCE_IDS=" + java_array(["fixture.synthetic"]) + ";\n"
    java += "    static final String[] DATA_ASSETS=" + java_array([fixture_name]) + ";\n"
    java += "    static final String[] DATA_DIGESTS=" + java_array([sha(fixture_bytes)]) + ";\n"
    java += "    static final int[] DATA_COUNTS=new int[]{2};\n}\n"
    (main_source / "java/io/github/refurbcheck/MalwareCatalog.java").write_text(java)

    build_script = CLONE / "tools/build_apk.py"
    original_build = build_script.read_text()
    if original_build.count('"io.github.refurbcheck"') != 2:
        raise RuntimeError("Unexpected namespace merge implementation")
    build_script.write_text(original_build.replace('"io.github.refurbcheck"', json.dumps(PACKAGE))
        .replace("Sign APK with the private release key", "Sign APK with disposable test identity")
        .replace("RefurbCheck 1.2.0 APK build verification", "TEST ONLY RefurbCheck validation APK build verification"))
    source_after = fingerprint(CLONE)
    changed = sorted(k for k in set(source_before) | set(source_after)
                     if source_before.get(k) != source_after.get(k))
    expected_java_change = "app/src/main/java/io/github/refurbcheck/MalwareCatalog.java"
    java_changed = [name for name in changed if name.endswith(".java")]
    if java_changed != [expected_java_change]:
        raise RuntimeError("Behavior-bearing Java unexpectedly changed: " + repr(java_changed))
    if fingerprint(PRODUCTION) != source_before:
        raise RuntimeError("Production source changed before validation build")
    output = ROOT / "RefurbCheck-1.2.0-validation-ONLY.apk"
    signing = ROOT / "private-test-signing"
    command = [sys.executable, str(build_script), "--sdk-root", str(ROOT.parent / "sdk"),
               "--keystore", str(signing / "disposable-validation-key.p12"),
               "--password-file", str(signing / "password.txt"), "--alias", "validation",
               "--output", str(output)]
    with (ROOT / "validation-build.log").open("w") as log:
        subprocess.run(command, stdout=log, stderr=subprocess.STDOUT, check=True)
    report = {
        "testOnly": True, "package": PACKAGE, "activity": "io.github.refurbcheck.MainActivity",
        "apk": str(output), "apkSha256": sha(output.read_bytes()),
        "builtAt": datetime.now(timezone.utc).isoformat(),
        "productionSourceBefore": source_before, "validationSourceAfter": source_after,
        "changedMainFiles": changed, "changedJavaFiles": java_changed,
        "behaviorBearingJavaUnchanged": True,
        "manifestOnlyAttributes": ["package", "label", "testOnly", "debuggable", "fully qualified existing activity"],
        "catalogSha256": sha(fixture_bytes), "catalogDigest": catalog_digest,
        "productionUnchangedAfterBuild": fingerprint(PRODUCTION) == source_before,
        "releaseKeyUsed": False,
    }
    (ROOT / "validation-build.json").write_bytes(encoded(report))
    print(json.dumps({k: v for k, v in report.items() if not k.endswith(("Before", "After"))}, indent=2))


if __name__ == "__main__":
    main()
