#!/usr/bin/env python3
"""Require the final instrumentation JSON, not just adb/am's shell exit code."""

import argparse
import json
from pathlib import Path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("log")
    parser.add_argument("--api", required=True, type=int)
    parser.add_argument("--app-sha256", required=True)
    parser.add_argument("--production-sha256", required=True)
    parser.add_argument("--summary-output")
    args = parser.parse_args()
    lines = Path(args.log).read_text(encoding="utf-8", errors="replace").splitlines()
    markers = [line[len("REFURBCHECK_SMOKE="):] for line in lines if line.startswith("REFURBCHECK_SMOKE=")]
    if len(markers) != 1:
        raise SystemExit("Expected exactly one final RefurbCheck smoke summary")
    summary = json.loads(markers[0])
    if args.summary_output:
        output = Path(args.summary_output)
        output.parent.mkdir(parents=True, exist_ok=True)
        output.write_text(json.dumps(summary, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    checks = summary.get("assertions")
    if summary.get("schema") != "refurbcheck-android-v13-smoke-v1" or summary.get("passed") is not True:
        raise SystemExit("Instrumentation failed: " + str(summary.get("failureMessage", "missing valid success verdict")))
    if summary.get("apiLevel") != args.api:
        raise SystemExit("Unexpected emulator API level")
    if not isinstance(checks, list) or len(checks) < 50 or summary.get("assertionCount") != len(checks):
        raise SystemExit("Incomplete runtime assertion list")
    if any(not isinstance(check, dict) or check.get("passed") is not True for check in checks):
        raise SystemExit("At least one runtime assertion did not pass")
    base = [row for row in summary.get("observations", {}).get("ownApkFiles", []) if row.get("fileId") == "base"]
    if len(base) != 1 or base[0].get("sha256") != args.app_sha256.lower():
        raise SystemExit("Runtime result is not bound to the expected production APK")
    original = summary.get("observations", {}).get("originalProductionApk", {})
    if (original.get("sha256") != args.production_sha256.lower()
            or original.get("archiveComplete") is not True
            or original.get("archiveStatus") != "COMPLETE"
            or original.get("entriesSkipped") != 0 or original.get("archiveIssues") != []):
        raise SystemExit("Original production APK identity or complete archive coverage is missing")
    codes = [line.strip() for line in lines if line.startswith("INSTRUMENTATION_CODE:")]
    if codes != ["INSTRUMENTATION_CODE: 0"]:
        raise SystemExit("Instrumentation did not finish with code 0")
    for key in ("actualGalaxyTest", "malwareDetectionRateMeasured", "hardwareIntegrityCertified", "fixtureApksInstalled"):
        if summary.get(key) is not False:
            raise SystemExit("Unexpected assurance claim: " + key)
    print(f"Android API {args.api}: {len(checks)} runtime assertions passed for APK {args.app_sha256.lower()}")


if __name__ == "__main__":
    main()
