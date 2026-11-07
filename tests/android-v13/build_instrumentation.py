#!/usr/bin/env python3
"""Build the isolated v1.3 smoke-test APK with official SDK tools and JDK 17.

Build the target production APK first. The test APK must use its signing key;
Android enforces this for instrumenting a non-debuggable release application.
Private signing files are read in place and must remain outside the repository.
Only test code and public fixtures are packaged, never production classes/keys.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import zipfile


APK_FIXTURES = (
    "v2-only-with-ecdsa-sha256-p256.apk",
    "v2-only-with-ecdsa-sha256-p256-digest-mismatch.apk",
    "v31-rsa-2048_2-tgt-34-1-tgt-28.apk",
    "v31-block-stripped-v3-attr-value-33.apk",
)
CERT_FIXTURES = ("google-v04-factory-blueline.pem", "google-v04-rkp-caiman.pem")
APK_LIBRARY_SHA256 = "83d7d7fec92ca21214d180e232a4594d2a1b6ee3b186a7b8ebf338d95e317040"


def run(command, capture=False):
    completed = subprocess.run([str(value) for value in command], check=True, text=True,
                               stdout=subprocess.PIPE if capture else None,
                               stderr=subprocess.STDOUT if capture else None)
    return completed.stdout if capture else ""


def sha256(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def signer_digest(output):
    result = re.findall(r"Signer #1 certificate SHA-256 digest: ([a-fA-F0-9]{64})", output)
    if len(result) != 1:
        raise RuntimeError("Expected exactly one APK signing-certificate digest")
    return result[0].lower()


def main():
    project = Path(__file__).resolve().parents[2]
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk-root", default=os.environ.get("ANDROID_SDK_ROOT") or os.environ.get("ANDROID_HOME"))
    parser.add_argument("--app-apk", required=True)
    parser.add_argument("--app-classes", default=str(project / "build/manual/classes"))
    parser.add_argument("--keystore", required=True)
    parser.add_argument("--password-file", required=True)
    parser.add_argument("--alias", default="refurbcheck")
    parser.add_argument("--output", default=str(project / "build/android-v13/RefurbCheck-v13-instrumentation.apk"))
    arguments = parser.parse_args()
    if not arguments.sdk_root:
        parser.error("Pass --sdk-root or set ANDROID_SDK_ROOT/ANDROID_HOME")
    sdk = Path(arguments.sdk_root).expanduser().resolve()
    build_tools = sdk / "build-tools/35.0.0"
    android_jar = sdk / "platforms/android-35/android.jar"
    app_apk = Path(arguments.app_apk).expanduser().resolve()
    production_apk = project / "release/RefurbCheck-1.3.0.apk"
    app_classes = Path(arguments.app_classes).expanduser().resolve()
    keystore = Path(arguments.keystore).expanduser().resolve()
    password = Path(arguments.password_file).expanduser().resolve()
    output = Path(arguments.output).expanduser().resolve()
    library = project / "app/libs/apksig-aosp-16.jar"
    java = shutil.which("java")
    if not java:
        parser.error("Java 17 including jdk.compiler is required")
    for secret in (keystore, password):
        if secret == project or project in secret.parents:
            parser.error("Keep signing material outside the repository")
    for required in (app_apk, production_apk, android_jar, build_tools / "aapt2", build_tools / "zipalign",
                     build_tools / "lib/d8.jar", build_tools / "lib/apksigner.jar", keystore, password,
                     app_classes / "io/github/refurbcheck/ScanReport.class"):
        if not required.is_file():
            parser.error("Required file missing: " + str(required))
    if sha256(library) != APK_LIBRARY_SHA256:
        raise RuntimeError("APK verification library digest differs from the reviewed build dependency")
    signer = [java, "-jar", build_tools / "lib/apksigner.jar"]
    target_verification = run(signer + ["verify", "--verbose", "--print-certs", app_apk], capture=True)
    target_signer = signer_digest(target_verification)
    badging = run([build_tools / "aapt2", "dump", "badging", app_apk], capture=True)
    if "package: name='io.github.refurbcheck'" not in badging:
        raise RuntimeError("Target APK must be the io.github.refurbcheck application")

    stage = project / "build/android-v13-stage"
    if stage.exists():
        shutil.rmtree(stage)
    assets = stage / "assets"
    fixtures = assets / "apk-fixtures"
    classes = stage / "classes"
    dex = stage / "dex"
    for directory in (assets, fixtures, classes, dex, output.parent):
        directory.mkdir(parents=True, exist_ok=True)
    hashes = {}
    for name in APK_FIXTURES:
        source = project / "tests/apksig-fixtures" / name
        shutil.copyfile(source, fixtures / name)
        hashes[name] = sha256(source)
    for name in CERT_FIXTURES:
        shutil.copyfile(project / "tests/attestation-fixtures" / name, assets / name)
    # Keep the publicly signed release untouched. The installed CI target may
    # have a different signing block, so it cannot substitute for these bytes.
    shutil.copyfile(production_apk, assets / "original-production.apk")
    with zipfile.ZipFile(production_apk) as archive:
        members = archive.infolist()
        production_release = {"sha256": sha256(production_apk), "sizeBytes": production_apk.stat().st_size,
                              "entryCount": len(members), "fileEntryCount": sum(not item.is_dir() for item in members)}
    config = {"schema": "refurbcheck-v13-smoke-config-v1", "appSha256": sha256(app_apk),
              "appSignerSha256": target_signer, "fixtureSha256": hashes, "productionRelease": production_release}
    (assets / "smoke-config.json").write_text(json.dumps(config, separators=(",", ":")) + "\n", encoding="utf-8")
    catalog = project / "data/catalog-updates/catalog-update.zip"
    shutil.copyfile(catalog, assets / "catalog-update.zip")
    with zipfile.ZipFile(catalog) as source, zipfile.ZipFile(
            assets / "catalog-invalid-signature.zip", "w", zipfile.ZIP_DEFLATED) as changed:
        changed_signature = False
        for member in source.infolist():
            value = source.read(member.filename)
            if member.filename == "manifest.sig":
                value = bytes([value[0] ^ 1]) + value[1:]
                changed_signature = True
            # Recompute the ZIP CRC so this tests cryptographic verification,
            # rather than only testing whether the ZIP reader detects damage.
            changed.writestr(member.filename, value)
        if not changed_signature:
            raise RuntimeError("Signed catalog is missing manifest.sig")

    resource_apk = stage / "resources.apk"
    run([build_tools / "aapt2", "link", "-o", resource_apk,
         "--manifest", project / "tests/android-v13/AndroidManifest.xml", "-I", android_jar,
         "--min-sdk-version", "26", "--target-sdk-version", "35", "--version-code", "1",
         "--version-name", "1.3-smoke", "-A", assets])
    run([java, "--module", "jdk.compiler/com.sun.tools.javac.Main", "--release", "8", "-encoding", "UTF-8",
         "-classpath", os.pathsep.join(str(value) for value in (android_jar, app_classes, library)),
         "-d", classes, project / "tests/android-v13/V13Instrumentation.java"])
    compile_only = stage / "target-compile-only.jar"
    with zipfile.ZipFile(compile_only, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(app_classes.rglob("*.class")):
            archive.write(path, path.relative_to(app_classes).as_posix())
    run([java, "-cp", build_tools / "lib/d8.jar", "com.android.tools.r8.D8", "--release", "--min-api", "26",
         "--lib", android_jar, "--classpath", compile_only, "--classpath", library,
         "--output", dex] + sorted(classes.rglob("*.class")))
    unsigned = stage / "unsigned.apk"
    shutil.copyfile(resource_apk, unsigned)
    with zipfile.ZipFile(unsigned, "a", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(dex.glob("classes*.dex")):
            archive.write(path, path.name)
    aligned = stage / "aligned.apk"
    run([build_tools / "zipalign", "-f", "-p", "4", unsigned, aligned])
    run(signer + ["sign", "--ks", keystore, "--ks-key-alias", arguments.alias,
                  "--ks-pass", "file:" + str(password), "--v1-signing-enabled", "true",
                  "--v2-signing-enabled", "true", "--v3-signing-enabled", "true",
                  "--v4-signing-enabled", "false", "--out", output, aligned])
    verification = run(signer + ["verify", "--verbose", "--print-certs", output], capture=True)
    if signer_digest(verification) != target_signer:
        raise RuntimeError("Instrumentation and target APK signing certificates differ")
    run([build_tools / "zipalign", "-c", "4", output])
    build_info = {"targetApkSha256": sha256(app_apk), "testApkSha256": sha256(output),
                  "originalProductionApkSha256": production_release["sha256"],
                  "targetAndTestSignerSha256": target_signer, "testOnlyApk": True,
                  "runtimeExecutionPerformedByBuild": False}
    (output.parent / "instrumentation-build-verification.json").write_text(
        json.dumps(build_info, indent=2) + "\n", encoding="utf-8")
    print("Test APK:", output)
    print("SHA-256:", build_info["testApkSha256"])
    print("Target SHA-256:", build_info["targetApkSha256"])


if __name__ == "__main__":
    main()
