#!/usr/bin/env bash
set -euo pipefail
project_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
refurbcheck_json_sha256="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
refurbcheck_json_jar="${REFURBCHECK_TEST_JSON_JAR:-${project_root}/build/test-deps/json.jar}"
if [[ ! -f "$refurbcheck_json_jar" ]]; then
    if [[ -n "${REFURBCHECK_TEST_JSON_JAR:-}" ]]; then
        printf '%s\n' "The supplied REFURBCHECK_TEST_JSON_JAR does not exist." >&2
        exit 1
    fi
    mkdir -p -- "$(dirname -- "$refurbcheck_json_jar")"
    refurbcheck_download="$(mktemp "${refurbcheck_json_jar}.download.XXXXXX")"
    trap 'rm -f -- "$refurbcheck_download"' EXIT
    curl --fail --location --silent --show-error --connect-timeout 10 --max-time 45 \
        --output "$refurbcheck_download" "https://repo.maven.apache.org/maven2/org/json/json/20240303/json-20240303.jar"
    if [[ "$(sha256sum -- "$refurbcheck_download" | cut -d ' ' -f 1)" != "$refurbcheck_json_sha256" ]]; then
        printf '%s\n' "JSON-java SHA-256 mismatch; refusing host test dependency." >&2
        exit 1
    fi
    mv -- "$refurbcheck_download" "$refurbcheck_json_jar"
    trap - EXIT
fi
if [[ "$(sha256sum -- "$refurbcheck_json_jar" | cut -d ' ' -f 1)" != "$refurbcheck_json_sha256" ]]; then
    printf '%s\n' "JSON-java SHA-256 mismatch; refusing host test dependency." >&2
    exit 1
fi
test_classes="$(mktemp -d)"
trap 'rm -rf -- "$test_classes"' EXIT
java --module jdk.compiler/com.sun.tools.javac.Main --release 8 -encoding UTF-8 -classpath "$refurbcheck_json_jar" -d "$test_classes" \
    "$project_root/app/src/main/java/io/github/refurbcheck/DerReader.java" \
    "$project_root/app/src/main/java/io/github/refurbcheck/AttestationRecord.java" \
    "$project_root/app/src/main/java/io/github/refurbcheck/AttestationChain.java" \
    "$project_root/app/src/main/java/io/github/refurbcheck/AttestationChecks.java" \
    "$project_root/app/src/main/java/io/github/refurbcheck/AttestationRevocations.java" \
    "$project_root/tests/AttestationTests.java"
java -cp "$test_classes:$refurbcheck_json_jar" io.github.refurbcheck.AttestationTests "$project_root"
