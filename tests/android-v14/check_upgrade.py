#!/usr/bin/env python3
"""Verify the exact public v1.3 -> v1.4 Android replacement and visible launcher."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import xml.etree.ElementTree as ET


SOURCE_SHA256 = "2d1b2c0d1222cf5089c0a30a10a81f884f8286f7b86cf214f82bb7f089f7efc8"
PRODUCTION_SIGNER = "d02b8c5cbcde0ad3fbd3eb9e4c66e28094a27cf4f7a8472d309f84d825184ceb"


def require(condition, message):
    if not condition:
        raise SystemExit(message)


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def package_fields(text):
    def field(pattern, name):
        values = re.findall(pattern, text, flags=re.MULTILINE)
        require(len(values) == 1, "Expected one package field: " + name)
        return values[0].strip()

    return {
        "versionCode": int(field(r"^\s*versionCode=(\d+)\b", "versionCode")),
        "versionName": field(r"^\s*versionName=(\S+)\s*$", "versionName"),
        "firstInstallTime": field(r"^\s*firstInstallTime=(.+)$", "firstInstallTime"),
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results", required=True)
    parser.add_argument("--source-apk", required=True)
    parser.add_argument("--target-apk", required=True)
    parser.add_argument("--api", required=True, type=int)
    args = parser.parse_args()
    results = Path(args.results)
    source_sha, target_sha = sha256(args.source_apk), sha256(args.target_apk)
    require(source_sha == SOURCE_SHA256, "Upgrade source is not the exact published v1.3 APK")
    require(target_sha != source_sha, "Upgrade target must be a distinct reviewed v1.4 APK")
    for filename in ("upgrade-source-signature.txt", "upgrade-target-signature.txt"):
        report = (results / filename).read_text(encoding="utf-8")
        digests = re.findall(r"Signer #1 certificate SHA-256 digest: ([a-fA-F0-9]{64})", report)
        require(digests == [PRODUCTION_SIGNER], "Both public APKs must retain the established production certificate")
        for evidence in ("Number of signers: 1", "Verified using v2 scheme (APK Signature Scheme v2): true",
                         "Verified using v3 scheme (APK Signature Scheme v3): true"):
            require(evidence in report, "Missing public APK signature verification: " + evidence)
    for filename in ("upgrade-source-install.txt", "upgrade-replace-install.txt"):
        lines = (results / filename).read_text(encoding="utf-8").splitlines()
        require("Success" in [line.strip() for line in lines], "Android installation did not succeed: " + filename)
    before = package_fields((results / "upgrade-source-package.txt").read_text(encoding="utf-8"))
    after = package_fields((results / "upgrade-target-package.txt").read_text(encoding="utf-8"))
    require(before["versionCode"] == 4 and before["versionName"] == "1.3.0", "Installed upgrade source has an unexpected version")
    require(after["versionCode"] == 5 and after["versionName"] == "1.4.0", "Android did not install the v1.4 update")
    require(before["firstInstallTime"] == after["firstInstallTime"], "Upgrade did not preserve the original installation record")
    for filename in ("upgrade-source-launch.txt", "release-launch.txt"):
        require("Status: ok" in (results / filename).read_text(encoding="utf-8"), "Production launcher failed: " + filename)
    pids = (results / "release-pid.txt").read_text(encoding="utf-8").split()
    require(pids and all(pid.isdecimal() for pid in pids), "Upgraded production app has no live process")
    hierarchy = ET.parse(results / "production-one-run.xml")
    nodes = list(hierarchy.iter("node"))
    own_nodes = [node for node in nodes if node.get("package") == "io.github.refurbcheck"]
    texts = [node.get("text", "") for node in own_nodes]
    require("한 번에 점검" in texts and any("REFURBCHECK" in text and "1.4.0" in text for text in texts),
            "UI hierarchy does not show the actual v1.4 one-run launcher")
    require(any("자료 확인" in text for text in texts) and any("전체 검사" in text for text in texts),
            "Production launcher does not expose the one-run stage progression")
    png = (results / "production-one-run.png").read_bytes()
    require(len(png) > 1000 and png[:8] == b"\x89PNG\r\n\x1a\n" and png[12:16] == b"IHDR", "Production screenshot is not a valid PNG capture")
    width, height = struct.unpack(">II", png[16:24])
    require(width >= 240 and height >= 240, "Production screenshot dimensions are implausible")
    summary = {
        "schema": "refurbcheck-v14-android-upgrade-v1", "passed": True, "apiLevel": args.api,
        "sourceApkSha256": source_sha, "targetApkSha256": target_sha,
        "productionSignerSha256": PRODUCTION_SIGNER, "sourcePackage": before, "targetPackage": after,
        "ordinaryReplacementInstall": True, "firstInstallTimePreserved": True,
        "productionLauncherVisible": True, "oneRunStagesVisible": True,
        "productionScreenshot": {"file": "production-one-run.png", "width": width, "height": height},
        "uiHierarchy": "production-one-run.xml", "actualGalaxyTest": False,
        "malwareDetectionRateMeasured": False, "hardwareIntegrityCertified": False,
    }
    (results / "upgrade-summary.json").write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(f"Android API {args.api}: exact v1.3 -> v1.4 ordinary upgrade passed; production launcher and stage UI captured.")


if __name__ == "__main__":
    main()
