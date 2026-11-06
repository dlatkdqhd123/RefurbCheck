#!/usr/bin/env python3
"""Build two benign, code-free APKs solely for validation of removal prompts.

This script never edits the shipping app, signature catalog or release folder.
The temporary signing identity is unrelated to the release signing identity.
"""
from datetime import datetime, timezone
from pathlib import Path
import hashlib
import json
import shutil
import secrets
import subprocess
import zipfile

ROOT = Path(__file__).resolve().parent
TOOLCHAIN = ROOT.parent
TOOLS = TOOLCHAIN / "sdk/build-tools/35.0.0"
ANDROID = TOOLCHAIN / "sdk/platforms/android-35/android.jar"
FIXTURES = [
    ("whole", "io.github.refurbcheck.fixture.whole", "Validation A Whole APK"),
    ("entry", "io.github.refurbcheck.fixture.entry", "Validation B Entry"),
]
PAYLOAD = (
    b"RefurbCheck 1.2 validation-only harmless text.\n"
    b"This file contains no executable code and is not a malware sample.\n"
    b"Synthetic reference: direct ZIP entry hash matching.\n"
)


def run(parts):
    result = subprocess.run([str(p) for p in parts], check=True, text=True,
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    return result.stdout + result.stderr


def sha(data):
    return hashlib.sha256(data).hexdigest()


def main():
    ROOT.mkdir(parents=True, exist_ok=True)
    key_dir = ROOT / "private-test-signing"
    key_dir.mkdir(exist_ok=True)
    key = key_dir / "disposable-validation-key.p12"
    password_file = key_dir / "password.txt"
    if key.exists():
        if not password_file.is_file():
            raise RuntimeError("Existing disposable test key has no password file")
        password = password_file.read_text(encoding="ascii")
    else:
        password = secrets.token_urlsafe(32)
        password_file.write_text(password, encoding="ascii")
        password_file.chmod(0o600)
        run([shutil.which("keytool"), "-genkeypair", "-keystore", key,
             "-storetype", "PKCS12", "-storepass", password, "-keypass", password,
             "-alias", "validation", "-keyalg", "RSA", "-keysize", "2048",
             "-validity", "3650", "-dname", "CN=Disposable RefurbCheck Validation",
             "-noprompt"])
    key.chmod(0o600)
    signer = [shutil.which("java"), "-jar", TOOLS / "lib/apksigner.jar"]
    records = []
    for kind, package, label in FIXTURES:
        work = ROOT / kind
        work.mkdir(exist_ok=True)
        manifest = work / "AndroidManifest.xml"
        manifest.write_text(f'''<?xml version="1.0" encoding="utf-8"?>
<manifest xmlns:android="http://schemas.android.com/apk/res/android"
    package="{package}" android:versionCode="1" android:versionName="1.0-test-only">
  <uses-sdk android:minSdkVersion="26" android:targetSdkVersion="35" />
  <application android:label="{label}" android:hasCode="false"
      android:allowBackup="false" android:debuggable="false" />
</manifest>
''', encoding="utf-8")
        command = [TOOLS / "aapt2", "link", "-I", ANDROID, "--manifest", manifest,
                   "-o", work / "unsigned.apk", "--min-sdk-version", "26",
                   "--target-sdk-version", "35"]
        if kind == "entry":
            assets = work / "assets"
            assets.mkdir(exist_ok=True)
            (assets / "harmless-fixture.txt").write_bytes(PAYLOAD)
            command += ["-A", assets]
        run(command)
        run([TOOLS / "zipalign", "-f", "4", work / "unsigned.apk", work / "aligned.apk"])
        apk = ROOT / (kind + "-fixture.apk")
        run(signer + ["sign", "--ks", key, "--ks-key-alias", "validation",
                      "--ks-pass", "file:" + str(password_file),
                      "--v1-signing-enabled", "true", "--v2-signing-enabled", "true",
                      "--v3-signing-enabled", "true", "--v4-signing-enabled", "false",
                      "--out", apk, work / "aligned.apk"])
        verification = run(signer + ["verify", "--verbose", "--print-certs", apk])
        badging = run([TOOLS / "aapt2", "dump", "badging", apk])
        (work / "signature-verification.txt").write_text(verification)
        (work / "badging.txt").write_text(badging)
        if "uses-permission:" in badging or "launchable-activity:" in badging:
            raise RuntimeError("Fixture acquired an unexpected permission/activity")
        apk_bytes = apk.read_bytes()
        with zipfile.ZipFile(apk) as archive:
            members = archive.namelist()
            if any(n.endswith((".dex", ".so")) for n in members):
                raise RuntimeError("Fixture contains executable Android code")
            if kind == "entry" and archive.read("assets/harmless-fixture.txt") != PAYLOAD:
                raise RuntimeError("Fixture text changed during packaging")
        reference_bytes = apk_bytes if kind == "whole" else PAYLOAD
        records.append({
            "kind": kind, "package": package, "label": label, "apk": str(apk),
            "apkSha256": sha(apk_bytes), "apkSize": len(apk_bytes),
            "expectedScope": "whole-apk" if kind == "whole" else "apk-entry",
            "expectedEntryName": "" if kind == "whole" else "assets/harmless-fixture.txt",
            "referenceSha256": sha(reference_bytes), "referenceSize": len(reference_bytes),
            "signatureName": "Fixture.Synthetic." + ("WholeAPK" if kind == "whole" else "DirectEntry"),
            "sourceId": "fixture.synthetic", "zipMembers": members,
            "executableCode": False, "requestedPermissions": [],
            "activities": [], "services": [], "receivers": [],
        })
    tsv = ("\n".join("\t".join([
        "sha256", r["referenceSha256"], str(r["referenceSize"]),
        r["signatureName"], "fixture.synthetic",
    ]) for r in records) + "\n").encode("ascii")
    (ROOT / "synthetic-only.tsv").write_bytes(tsv)
    report = {
        "schema": "refurbcheck-test-fixtures-v1",
        "createdAt": datetime.now(timezone.utc).isoformat(),
        "purpose": "Android emulator only: actual scan/preflight/uninstall-cancel/confirm/queue/rescan validation",
        "testOnly": True, "realMalwareSamplesUsed": False,
        "shippingCatalogEdited": False, "releaseSigningKeyUsed": False,
        "syntheticDatasetSha256": sha(tsv), "syntheticEntryCount": len(records),
        "fixtures": records,
    }
    (ROOT / "fixtures.json").write_text(json.dumps(report, indent=2) + "\n")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
