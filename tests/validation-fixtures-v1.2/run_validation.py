#!/usr/bin/env python3
"""Real Android confirmation workflow with benign test-only reference hashes.

Only execute after the parent transfers exclusive emulator UI ownership.
The first phase stops before any removal; the cancellation phase stops after
capturing the report; the resume phase approves only these two benign fixtures.
"""
from datetime import datetime, timezone
from pathlib import Path
import argparse
import hashlib
import json
import time
from validation_client import (
    ROOT, EVIDENCE, PACKAGE, adb, await_ui, capture, dump, export_report,
    installed, nodes, packages, scroll_to, tap, texts,
)

STATE = EVIDENCE / "test-state.json"
FIXTURE_INFO = json.loads((ROOT / "fixtures.json").read_text())
FIXTURES = FIXTURE_INFO["fixtures"]
BY_PACKAGE = {item["package"]: item for item in FIXTURES}
BY_LABEL = {item["label"]: item for item in FIXTURES}
state = json.loads(STATE.read_text()) if STATE.exists() else {
    "schema": "refurbcheck-test-only-remediation-v1",
    "startedAt": datetime.now(timezone.utc).isoformat(),
    "status": "IN_PROGRESS", "checks": [], "phases": [],
    "physicalGalaxyTested": False, "realMalwareSamplesUsed": False,
    "environment": {"api": 26, "abi": "x86", "softwareEmulator": True},
    "fixtureDescription": FIXTURE_INFO,
}


def save():
    STATE.write_text(json.dumps(state, ensure_ascii=False, indent=2) + "\n")


def checked(name, condition, details):
    record = {"check": name, "passed": bool(condition), "details": details,
              "at": datetime.now(timezone.utc).isoformat()}
    state["checks"].append(record)
    save()
    print(json.dumps(record, ensure_ascii=False), flush=True)
    if not condition:
        raise AssertionError(name)


def target(tree):
    found = [label for label in BY_LABEL if label in texts(tree)]
    if "com.android.packageinstaller" not in packages(tree) or len(found) != 1:
        return None
    if "Do you want to uninstall this app?" not in texts(tree):
        return None
    if len(nodes(tree, resource_id="android:id/button1")) != 1 or len(nodes(tree, resource_id="android:id/button2")) != 1:
        return None
    return BY_LABEL[found[0]]


def idle(tree):
    return PACKAGE in packages(tree) and "종합 점검 중" not in texts(tree) and (
        "이번 점검 결과" in texts(tree) or "확인하고 바로 조치하기" in texts(tree))


def first():
    checked("API26 emulator available", adb(["shell", "getprop", "ro.build.version.sdk"])["stdout"].strip() == "26", "Queued API26 software emulator")
    validation = ROOT / "RefurbCheck-1.2.0-validation-ONLY.apk"
    build = json.loads((ROOT / "validation-build.json").read_text())
    checked("Validation artifact digest pinned", hashlib.sha256(validation.read_bytes()).hexdigest() == build["apkSha256"], build["apkSha256"])
    checked("Behavior-bearing Java unchanged", build["behaviorBearingJavaUnchanged"] and build["productionUnchangedAfterBuild"], build["changedJavaFiles"])
    state["validationBuild"] = {key: build[key] for key in (
        "package", "activity", "apkSha256", "catalogSha256", "catalogDigest",
        "changedJavaFiles", "behaviorBearingJavaUnchanged", "releaseKeyUsed")}
    adb(["install", "-r", "-t", str(validation)], timeout=180)
    for fixture in FIXTURES:
        checked("Benign fixture digest pinned: " + fixture["kind"],
                hashlib.sha256(Path(fixture["apk"]).read_bytes()).hexdigest() == fixture["apkSha256"], fixture["apkSha256"])
        adb(["install", "-r", fixture["apk"]], timeout=120)
        checked("Benign fixture installed: " + fixture["kind"], installed(fixture["package"]), fixture["package"])
    adb(["shell", "am", "force-stop", PACKAGE])
    launch = adb(["shell", "am", "start", "-W", "-n", PACKAGE + "/io.github.refurbcheck.MainActivity"], timeout=120)
    checked("Validation activity launched", "Error:" not in launch["stdout"], launch["stdout"])
    state["initialLaunchWithoutAppButtonPress"] = True
    save()
    first_prompt()


def first_prompt():
    tree = await_ui("first-automatic-confirm-continued", lambda ui: target(ui) is not None, timeout=600)
    item = target(tree)
    state["firstPromptPackage"] = item["package"]
    checked("Scan automatically opens Android uninstall confirmation", item is not None, {"package": item["package"], "ui": texts(tree)})
    checked("Neither fixture removed without approval", all(installed(item["package"]) for item in FIXTURES), "Both benign fixtures remain before the Android approval")
    capture("01-first-automatic-confirm")
    state["phases"].append("first")
    save()


def cancel():
    tree = dump("cancel-before")
    item = target(tree)
    checked("Cancel targets the observed first fixture", item is not None and item["package"] == state["firstPromptPackage"], texts(tree))
    tap(tree, resource_id="android:id/button2")
    checked("Android cancellation preserves both packages", all(installed(item["package"]) for item in FIXTURES), list(BY_PACKAGE))
    tree = await_ui("rescan-after-cancel", idle, timeout=600)
    capture("02-result-after-cancel")
    tap(tree, text="조치")
    tree = dump("cancel-paused-remediation")
    checked("Cancellation shows blocked removal explanation", any("삭제가 확인되지 않은 앱" == value for value in texts(tree)), texts(tree))
    mode = [node for node in tree.iter("node") if node.get("class") == "android.widget.Switch"]
    checked("Automatic post-reset mode is enabled by default", len(mode) == 1 and mode[0].get("checked") == "true", [node.attrib for node in mode])
    capture("03-cancel-queue-paused")
    report = export_report("after-cancel")
    evidence = report["evidence"]
    database = evidence["malwareDatabase"]
    checked("Only two synthetic references loaded", database["loaded"] and database["entryCount"] == 2
            and database["catalog"]["countsBySource"] == {"fixture.synthetic": 2}, {"loaded": database["loaded"], "entryCount": database["entryCount"], "counts": database["catalog"]["countsBySource"]})
    inventory = {row["packageName"]: row for row in report["inventory"]}
    checked("Report has both matching fixtures", evidence["malwareCoverage"]["matchingPackages"] == 2
            and all(item["package"] in inventory for item in FIXTURES), evidence["malwareCoverage"])
    for item in FIXTURES:
        row = inventory[item["package"]]
        matches = row["malwareReferenceMatches"]
        exact = len(matches) == 1 and matches[0]["sourceId"] == "fixture.synthetic" \
            and matches[0]["scope"] == item["expectedScope"] \
            and matches[0]["entryName"] == item["expectedEntryName"] \
            and matches[0]["digest"] == item["referenceSha256"] \
            and matches[0]["observedSize"] == item["referenceSize"] \
            and matches[0]["outerApkSha256"] == item["apkSha256"]
        checked("Exact live hash and scope: " + item["kind"], exact and row["malwareInspectionComplete"], matches)
    log = evidence["remediationLog"]
    state["cancelReport"] = {"reportId": report["reportId"], "startedAt": report["startedAt"],
                             "completedAt": report["completedAt"], "matchingPackages": 2,
                             "remediationLog": log}
    checked("Preflight preceded the system prompt", [entry["outcome"] for entry in log[:2]] == ["AUTO_REMOVAL_PREFLIGHT", "SCREEN_OPENED"], log)
    checked("Cancel outcome explicitly records package still present", any(entry["outcome"] == "PACKAGE_STILL_PRESENT" for entry in log), log)
    checked("Cancel pauses the queue before the second prompt", sum(entry["outcome"] == "SCREEN_OPENED" for entry in log) == 1,
            {"opened": sum(entry["outcome"] == "SCREEN_OPENED" for entry in log), "log": log})
    tree = dump("cancel-still-paused-after-export")
    checked("Queue stays paused while examining and exporting results", PACKAGE in packages(tree)
            and "com.android.packageinstaller" not in packages(tree)
            and all(installed(item["package"]) for item in FIXTURES), {"uiPackages": packages(tree), "fixturesPresent": list(BY_PACKAGE)})
    state["phases"].append("cancel")
    save()


def resume():
    tree = dump("resume-before")
    tap(tree, text="조치")
    tree = scroll_to("다시 점검하고 조치 계속", "resume-button")
    capture("04-rescan-and-continue")
    tap(tree, text="다시 점검하고 조치 계속")
    removed = []
    for position in range(2):
        tree = await_ui("approval-" + str(position + 1), lambda ui: target(ui) is not None, timeout=600 if position == 0 else 180)
        item = target(tree)
        checked("Sequential prompt identifies remaining benign fixture " + str(position + 1),
                item["package"] in BY_PACKAGE and item["package"] not in removed and installed(item["package"]),
                {"package": item["package"], "ui": texts(tree)})
        capture("05-confirm-first" if position == 0 else "06-confirm-second")
        tap(tree, resource_id="android:id/button1")
        deadline = time.monotonic() + 90
        while installed(item["package"]) and time.monotonic() < deadline:
            time.sleep(2)
        checked("Android approval removes fixture " + str(position + 1), not installed(item["package"]), item["package"])
        removed.append(item["package"])
    state["approvedRemovalOrder"] = removed
    tree = await_ui("final-full-rescan", idle, timeout=600)
    tap(tree, text="결과")
    await_ui("final-results-tab", lambda ui: "이번 점검 결과" in texts(ui), timeout=120)
    capture("07-final-result")
    report = export_report("final")
    evidence = report["evidence"]
    present = {row["packageName"] for row in report["inventory"]}
    checked("Final rescan no longer contains either fixture", not present.intersection(BY_PACKAGE)
            and all(not installed(item["package"]) for item in FIXTURES), {"fixturePackages": list(BY_PACKAGE), "inventoryCount": len(present)})
    checked("Final synthetic matching package count is zero", evidence["malwareCoverage"]["matchingPackages"] == 0, evidence["malwareCoverage"])
    checked("Final rescan is a fresh report", report["reportId"] != state["cancelReport"]["reportId"]
            and report["startedAt"] > state["cancelReport"]["completedAt"], {"reportId": report["reportId"], "startedAt": report["startedAt"], "completedAt": report["completedAt"]})
    log = evidence["remediationLog"]
    outcomes = [entry["outcome"] for entry in log]
    checked("Two approved removals recorded after earlier cancellation", outcomes.count("PACKAGE_NOT_PRESENT") == 2
            and outcomes.count("PACKAGE_STILL_PRESENT") == 1
            and outcomes.count("AUTO_REMOVAL_PREFLIGHT") == 3
            and outcomes.count("SCREEN_OPENED") == 3, log)
    checked("Android approval remains required", evidence["silentRemoval"] is False
            and evidence["systemRemovalApprovalRequired"] is True, {"silentRemoval": evidence["silentRemoval"], "systemRemovalApprovalRequired": evidence["systemRemovalApprovalRequired"]})
    state["finalReport"] = {"reportId": report["reportId"], "startedAt": report["startedAt"],
                            "completedAt": report["completedAt"], "matchingPackages": 0,
                            "remediationLog": log, "malwareCoverage": evidence["malwareCoverage"]}
    tree = dump("final-remediation-before")
    tap(tree, text="조치")
    capture("08-final-remediation")
    state["phases"].append("resume")
    state["status"] = "PASS"
    state["completedAt"] = datetime.now(timezone.utc).isoformat()
    save()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("phase", choices=["first", "first-prompt", "cancel", "resume"])
    parser.add_argument("--exclusive-ui-granted", action="store_true")
    args = parser.parse_args()
    if not args.exclusive_ui_granted:
        parser.error("Wait for explicit parent handoff of the shared emulator UI")
    try:
        globals()[args.phase.replace("-", "_")]()
    except Exception as error:
        state["lastError"] = repr(error)
        state["status"] = "BLOCKED_OR_FAILED"
        save()
        raise
