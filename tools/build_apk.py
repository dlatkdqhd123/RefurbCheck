#!/usr/bin/env python3
"""Build RefurbCheck with the official Android SDK, without Gradle downloads.

Example:
  python3 tools/build_apk.py --sdk-root /path/to/android-sdk \
    --keystore /private/refurbcheck.p12 --password-file /private/password.txt

The keystore and password must stay outside this repository. The script never
generates or embeds a shared/debug signing key. JDK 17 (including jdk.compiler),
Android platform 35 and build-tools 35.0.0 are required.
"""

import argparse
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import xml.etree.ElementTree as ET
import zipfile


def run(command, *, capture=False):
    # Print executable and phase only; never print signing material.
    result = subprocess.run(
        [str(part) for part in command],
        check=True,
        text=True,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.STDOUT if capture else None,
    )
    return result.stdout if capture else ""


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sdk-root", default=os.environ.get("ANDROID_SDK_ROOT"))
    parser.add_argument("--keystore", required=True)
    parser.add_argument("--password-file", required=True)
    parser.add_argument("--alias", default="refurbcheck")
    parser.add_argument("--output", default="dist/RefurbCheck-1.2.0.apk")
    args = parser.parse_args()
    project = Path(__file__).resolve().parents[1]
    if not args.sdk_root:
        parser.error("Provide --sdk-root or ANDROID_SDK_ROOT")
    sdk = Path(args.sdk_root).expanduser().resolve()
    build_tools = sdk / "build-tools" / "35.0.0"
    android_jar = sdk / "platforms" / "android-35" / "android.jar"
    keystore = Path(args.keystore).expanduser().resolve()
    password = Path(args.password_file).expanduser().resolve()
    for secret in (keystore, password):
        if secret == project or project in secret.parents:
            parser.error("Signing material must be outside the source repository")
        if not secret.is_file():
            parser.error("Signing material file is missing")
    required = [android_jar, build_tools / "aapt2", build_tools / "zipalign",
                build_tools / "lib" / "d8.jar", build_tools / "lib" / "apksigner.jar"]
    for path in required:
        if not path.is_file():
            parser.error("Missing Android SDK component: " + str(path))
    java = shutil.which("java")
    if not java:
        parser.error("A Java 17 JDK is required")
    main_source = project / "app" / "src" / "main"
    dependencies = [project / "app" / "libs" / "apksig-android-4.4.0.jar"]
    if hashlib.sha256(dependencies[0].read_bytes()).hexdigest() != "530fcc4384889108bf85b4c816cfe354604dd38654b30d81fc046a817e1c10e0":
        raise RuntimeError("Pinned apksig-android dependency digest mismatch")
    if not (main_source / "AndroidManifest.xml").is_file():
        parser.error("AndroidManifest.xml is not ready")
    build = project / "build" / "manual"
    if build.exists():
        shutil.rmtree(build)
    generated = build / "generated"
    classes = build / "classes"
    dex = build / "dex"
    for path in (generated, classes, dex):
        path.mkdir(parents=True, exist_ok=True)
    # AGP supplies namespace/applicationId while merging a namespace-only source
    # manifest. Mirror that build step locally without changing the source XML.
    ET.register_namespace("android", "http://schemas.android.com/apk/res/android")
    manifest_tree = ET.parse(main_source / "AndroidManifest.xml")
    manifest_root = manifest_tree.getroot()
    existing_package = manifest_root.get("package")
    if existing_package and existing_package != "io.github.refurbcheck":
        raise RuntimeError("Unexpected manifest package: " + existing_package)
    manifest_root.set("package", "io.github.refurbcheck")
    merged_manifest = build / "AndroidManifest.xml"
    manifest_tree.write(merged_manifest, encoding="utf-8", xml_declaration=True)
    output = Path(args.output)
    if not output.is_absolute():
        output = project / output
    output.parent.mkdir(parents=True, exist_ok=True)
    print("[1/6] Compile Android resources", flush=True)
    resource_zip = build / "compiled-res.zip"
    run([build_tools / "aapt2", "compile", "--dir", main_source / "res", "-o", resource_zip])
    resource_apk = build / "resources.apk"
    link_command = [build_tools / "aapt2", "link", "-o", resource_apk,
                    "--manifest", merged_manifest,
                    "--java", generated, "-I", android_jar,
                    "--min-sdk-version", "26", "--target-sdk-version", "35",
                    "--version-code", "3", "--version-name", "1.2.0"]
    if (main_source / "assets").exists():
        link_command += ["-A", main_source / "assets"]
    run(link_command + [resource_zip])
    print("[2/6] Compile Java source", flush=True)
    sources = sorted((main_source / "java").rglob("*.java")) + sorted(generated.rglob("*.java"))
    if not sources:
        raise RuntimeError("No Java source files were found")
    run([java, "com.sun.tools.javac.Main", "-encoding", "UTF-8",
         "--release", "8", "-classpath", os.pathsep.join(str(p) for p in [android_jar] + dependencies),
         "-d", classes] + sources)
    print("[3/6] Generate Android DEX bytecode", flush=True)
    compiled = sorted(classes.rglob("*.class"))
    run([java, "-cp", build_tools / "lib" / "d8.jar", "com.android.tools.r8.D8",
         "--release", "--min-api", "26", "--lib", android_jar,
         "--output", dex] + compiled + dependencies)
    print("[4/6] Package and align APK", flush=True)
    unsigned = build / "unsigned.apk"
    shutil.copyfile(resource_apk, unsigned)
    with zipfile.ZipFile(unsigned, "a", compression=zipfile.ZIP_DEFLATED) as archive:
        for dex_file in sorted(dex.glob("classes*.dex")):
            archive.write(dex_file, dex_file.name)
    aligned = build / "aligned.apk"
    run([build_tools / "zipalign", "-f", "-p", "4", unsigned, aligned])
    print("[5/6] Sign APK with the private release key", flush=True)
    signer = [java, "-jar", build_tools / "lib" / "apksigner.jar"]
    run(signer + ["sign", "--ks", keystore, "--ks-key-alias", args.alias,
                  "--ks-pass", "file:" + str(password),
                  "--v1-signing-enabled", "true", "--v2-signing-enabled", "true",
                  "--v3-signing-enabled", "true", "--v4-signing-enabled", "false",
                  "--out", output, aligned])
    print("[6/6] Verify signatures, alignment and APK manifest", flush=True)
    verification = run(signer + ["verify", "--verbose", "--print-certs", output], capture=True)
    alignment = run([build_tools / "zipalign", "-c", "-v", "4", output], capture=True)
    manifest = run([build_tools / "aapt2", "dump", "badging", output], capture=True)
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    summary = ("RefurbCheck 1.2.0 APK build verification\n"
               "Build tools: official Android SDK 35.0.0; compile API 35\n"
               "Runtime device/emulator execution is not established by this build script.\n\n"
               + verification + "\n" + alignment + "\n" + manifest
               + "\nAPK SHA-256: " + digest + "\n")
    (output.parent / "apk-build-verification.txt").write_text(summary, encoding="utf-8")
    (output.parent / (output.name + ".sha256")).write_text(
        digest + "  " + output.name + "\n", encoding="ascii")
    print(verification)
    print("APK:", output)
    print("SHA-256:", digest)


if __name__ == "__main__":
    try:
        main()
    except subprocess.CalledProcessError as error:
        if error.stdout:
            print(error.stdout, file=sys.stderr)
        sys.exit(error.returncode)
