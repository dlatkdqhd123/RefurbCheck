"""Sequential queued ADB helpers; use only while this test owns emulator UI."""
from datetime import datetime, timezone
from pathlib import Path
import json
import re
import shutil
import subprocess
import sys
import time
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parent
TOOLCHAIN = ROOT.parent
EVIDENCE = ROOT / "evidence"
EVIDENCE.mkdir(exist_ok=True)
PACKAGE = "io.github.refurbcheck.validation"
EVENTS = EVIDENCE / "commands.jsonl"


def event(value):
    record = {"at": datetime.now(timezone.utc).isoformat(), **value}
    with EVENTS.open("a") as output:
        output.write(json.dumps(record, ensure_ascii=False) + "\n")


def request(payload):
    begin = time.monotonic()
    result = subprocess.run([sys.executable, str(TOOLCHAIN / "send_smoke_command.py")],
                            input=json.dumps(payload), text=True, capture_output=True,
                            timeout=max(240, payload.get("timeout", 60) + 120))
    if result.returncode:
        event({"request": payload, "clientError": result.stdout + result.stderr})
        raise RuntimeError(result.stdout + result.stderr)
    response = json.loads(result.stdout)
    event({"request": payload, "response": response, "elapsedSeconds": round(time.monotonic() - begin, 3)})
    if response.get("error") or response.get("exit", 0):
        raise RuntimeError(json.dumps(response, ensure_ascii=False))
    return response


def adb(args, timeout=60):
    return request({"action": "adb", "args": args, "timeout": timeout})


def texts(tree):
    return [node.get("text") for node in tree.iter("node") if node.get("text")]


def packages(tree):
    return sorted({node.get("package") for node in tree.iter("node") if node.get("package")})


def dump(name):
    remote = "/sdcard/refurbcheck-validation-ui.xml"
    # UIAutomator can return exit 0 plus a null-root diagnostic during an
    # activity transition. Retry reads only; never replay a UI action.
    for attempt in range(3):
        adb(["shell", "rm", "-f", remote])
        result = adb(["shell", "uiautomator", "dump", remote], timeout=90)
        xml = adb(["exec-out", "cat", remote])["stdout"]
        try:
            tree = ET.fromstring(xml)
        except ET.ParseError:
            (EVIDENCE / f"{name}-read-attempt-{attempt}.txt").write_text(json.dumps(result) + "\n" + xml)
            if attempt == 2:
                raise
            time.sleep(2)
            continue
        (EVIDENCE / (name + ".xml")).write_text(xml)
        return tree


def capture(name):
    result = request({"action": "capture", "name": "validation-" + name, "timeout": 180})
    for key, suffix in (("screenshot", ".png"), ("ui", ".xml")):
        source = Path(result[key])
        shutil.copy2(source, EVIDENCE / (name + suffix))
    log = Path(result["screenshot"]).with_name("validation-" + name + "-logcat.txt")
    if log.is_file():
        shutil.copy2(log, EVIDENCE / (name + "-logcat.txt"))
    return ET.parse(EVIDENCE / (name + ".xml")).getroot()


def nodes(tree, text=None, resource_id=None):
    return [node for node in tree.iter("node")
            if (text is None or node.get("text") == text)
            and (resource_id is None or node.get("resource-id") == resource_id)]


def tap_node(node):
    x1, y1, x2, y2 = map(int, re.findall(r"\d+", node.get("bounds", "")))
    if x2 <= x1 or y2 <= y1:
        raise RuntimeError("Observed node has no visible bounds")
    return adb(["shell", "input", "tap", str((x1 + x2) // 2), str((y1 + y2) // 2)])


def tap(tree, text=None, resource_id=None):
    found = nodes(tree, text, resource_id)
    if len(found) != 1:
        raise RuntimeError(f"Expected one observed UI node {text=} {resource_id=}; {texts(tree)}")
    return tap_node(found[0])


def scroll_to(label, prefix, limit=15):
    for count in range(limit + 1):
        tree = dump(f"{prefix}-{count}")
        matches = [node for node in nodes(tree, text=label)
                   if node.get("clickable") == "true" and node.get("class") == "android.widget.Button"]
        if len(matches) == 1:
            return tree
        scrolls = [node for node in tree.iter("node") if node.get("scrollable") == "true"]
        if not scrolls:
            break
        x1, y1, x2, y2 = map(int, re.findall(r"\d+", scrolls[0].get("bounds", "")))
        x = (x1 + x2) // 2
        adb(["shell", "input", "swipe", str(x), str(y1 + (y2 - y1) * 8 // 10),
             str(x), str(y1 + (y2 - y1) * 2 // 10), "300"])
    raise RuntimeError("Observed button not found: " + label)


def installed(package):
    output = adb(["shell", "pm", "list", "packages", package])["stdout"]
    return ("package:" + package) in output.splitlines()


def await_ui(name, predicate, timeout=420):
    deadline = time.monotonic() + timeout
    count = 0
    while time.monotonic() < deadline:
        tree = dump(f"{name}-poll-{count}")
        print(json.dumps({"waitingFor": name, "ui": texts(tree)[:8]}, ensure_ascii=False), flush=True)
        if predicate(tree):
            return tree
        count += 1
        # UIAutomator competes with the software emulator's scanner for CPU.
        # Progress polling need not run repeatedly while a whole scan is active.
        time.sleep(20 if "종합 점검 중" in texts(tree) else 3)
    raise RuntimeError("UI wait expired: " + name)


def export_report(name):
    tree = dump(name + "-before-export")
    tap(tree, text="결과")
    tree = scroll_to("결과 JSON 저장", name + "-export-button")
    tap(tree, text="결과 JSON 저장")
    tree = await_ui(name + "-document-picker", lambda ui: "com.android.documentsui" in packages(ui), timeout=120)
    report = adb(["exec-out", "run-as", PACKAGE, "cat", "cache/pending-refurbcheck-report.json"])["stdout"]
    parsed = json.loads(report)
    (EVIDENCE / (name + "-report.json")).write_text(json.dumps(parsed, ensure_ascii=False, indent=2) + "\n")
    adb(["shell", "input", "keyevent", "4"])
    return parsed
