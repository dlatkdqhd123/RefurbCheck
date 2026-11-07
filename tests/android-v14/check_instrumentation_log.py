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
    if summary.get("schema") != "refurbcheck-android-v14-smoke-v1" or summary.get("passed") is not True:
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
    lifecycle = summary.get("observations", {}).get("oneRunLifecycle", {})
    for key in ("stopBlocksAutomaticActions", "backgroundResumePreservesCycle", "freshLauncherStartsNewCycle",
                "rotationPreservesCycle", "completionKeepsAssuranceLimits", "realDisplayRotation",
                "taskResumedWithoutLauncherIntent", "realStopButtonClicked", "automaticFlowCompleted"):
        if lifecycle.get(key) is not True:
            raise SystemExit("Missing completed real Activity lifecycle scenario: " + key)
    launched = lifecycle.get("launched", {})
    first_run = launched.get("runId")
    second_run = lifecycle.get("freshLauncher", {}).get("runId")
    if not isinstance(first_run, str) or not first_run or not isinstance(second_run, str) or not second_run or first_run == second_run:
        raise SystemExit("Launcher entries did not produce two distinct recorded cycles")
    for key in ("stopped", "rotatedStopped", "resumedStopped"):
        item = lifecycle.get(key, {})
        if item.get("runId") != first_run or item.get("phase") != "CANCELLED" or item.get("cancelled") is not True:
            raise SystemExit("Cancellation was lost during lifecycle scenario: " + key)
    for key in ("freshLauncher", "rotatedFresh", "resumedFresh", "completed"):
        item = lifecycle.get(key, {})
        if item.get("runId") != second_run or item.get("cancelled") is not False:
            raise SystemExit("New cycle identity changed or retained cancellation: " + key)
    completed = lifecycle.get("completed", {})
    if (completed.get("phase") != "COMPLETE" or completed.get("initialScanComplete") is not True
            or completed.get("scanCount") != 1 or completed.get("recheckPerformed") is not False
            or any(completed.get(key) != 0 for key in ("eligibleCount", "remainingRemovalCount", "removedCount", "attemptedCount"))):
        raise SystemExit("Benign one-run completion is missing, duplicated or invents removal actions")
    for name in ("launched", "stopped", "rotatedStopped", "resumedStopped", "freshLauncher", "rotatedFresh", "resumedFresh", "completed"):
        item = lifecycle.get(name, {})
        if any(item.get(key) is not False for key in ("factoryOriginalVerified", "malwareAbsenceVerified", "physicalHardwareVerified", "silentRemoval")):
            raise SystemExit("Unsupported assurance claim in one-run state: " + name)
        if item.get("systemRemovalApprovalRequired") is not True:
            raise SystemExit("Android removal approval requirement missing: " + name)
    if lifecycle.get("actualUninstallationPerformed") is not False or lifecycle.get("allRequiredDomainsVerified") is not False:
        raise SystemExit("Runtime test cannot certify device safety or claim an untested uninstallation")
    catalog_cancel = summary.get("observations", {}).get("manualCatalogCancellation", {})
    for key in ("realStopButtonClicked", "cancellationTokenSetBeforeWorkerRelease", "lateCallbackDidNotRestart",
                "reportIdentityPreserved", "preDownloadCancellationRecorded"):
        if catalog_cancel.get(key) is not True:
            raise SystemExit("Missing manual catalog cancellation regression evidence: " + key)
    requested, after = catalog_cancel.get("requested", {}), catalog_cancel.get("after", {})
    if (requested.get("catalogUpdateCancellationRequested") is not True
            or requested.get("runId") != second_run or requested.get("phase") != "CANCELLED"
            or after.get("runId") != second_run or after.get("phase") != "CANCELLED"
            or after.get("scanCount") != completed.get("scanCount")
            or after.get("catalogUpdateCancellationRequested") is not False):
        raise SystemExit("Manual catalog cancellation did not retain its cycle after the late callback")
    codes = [line.strip() for line in lines if line.startswith("INSTRUMENTATION_CODE:")]
    if codes != ["INSTRUMENTATION_CODE: 0"]:
        raise SystemExit("Instrumentation did not finish with code 0")
    for key in ("actualGalaxyTest", "malwareDetectionRateMeasured", "hardwareIntegrityCertified", "fixtureApksInstalled"):
        if summary.get(key) is not False:
            raise SystemExit("Unexpected assurance claim: " + key)
    print(f"Android API {args.api}: {len(checks)} runtime assertions passed for APK {args.app_sha256.lower()}")


if __name__ == "__main__":
    main()
