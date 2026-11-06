#!/usr/bin/env bash
set -euo pipefail
refurbcheck_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
refurbcheck_json_sha256="3cf6cd6892e32e2b4c1c39e0f52f5248a2f5b37646fdfbb79a66b46b618414ed"
refurbcheck_json_jar="${REFURBCHECK_TEST_JSON_JAR:-${refurbcheck_root}/build/test-deps/json.jar}"
refurbcheck_classes="${refurbcheck_root}/build/inventory-policy-tests"
refurbcheck_java="${REFURBCHECK_JAVA:-java}"
if [[ ! -f "$refurbcheck_json_jar" ]]; then
    if [[ -n "${REFURBCHECK_TEST_JSON_JAR:-}" ]]; then
        printf '%s\n' 'The supplied REFURBCHECK_TEST_JSON_JAR does not exist.' >&2
        exit 1
    fi
    mkdir -p -- "$(dirname -- "$refurbcheck_json_jar")"
    refurbcheck_download="$(mktemp "${refurbcheck_json_jar}.download.XXXXXX")"
    trap 'rm -f -- "$refurbcheck_download"' EXIT
    curl --fail --location --silent --show-error --connect-timeout 10 --max-time 45 \
        --output "$refurbcheck_download" 'https://repo.maven.apache.org/maven2/org/json/json/20240303/json-20240303.jar'
    refurbcheck_actual="$(sha256sum -- "$refurbcheck_download")"
    [[ "${refurbcheck_actual%% *}" == "$refurbcheck_json_sha256" ]] || { printf '%s\n' 'JSON-java SHA-256 mismatch.' >&2; exit 1; }
    mv -- "$refurbcheck_download" "$refurbcheck_json_jar"
    trap - EXIT
fi
refurbcheck_actual="$(sha256sum -- "$refurbcheck_json_jar")"
[[ "${refurbcheck_actual%% *}" == "$refurbcheck_json_sha256" ]] || { printf '%s\n' 'JSON-java SHA-256 mismatch.' >&2; exit 1; }
mkdir -p -- "$refurbcheck_classes"
"$refurbcheck_java" --module jdk.compiler/com.sun.tools.javac.Main --release 8 -encoding UTF-8 \
    -classpath "$refurbcheck_json_jar" -d "$refurbcheck_classes" \
    "$refurbcheck_root/app/src/main/java/io/github/refurbcheck/Finding.java" \
    "$refurbcheck_root/app/src/main/java/io/github/refurbcheck/ScanReport.java" \
    "$refurbcheck_root/app/src/main/java/io/github/refurbcheck/SignatureLineage.java" \
    "$refurbcheck_root/app/src/main/java/io/github/refurbcheck/BaselineComparator.java" \
    "$refurbcheck_root/app/src/main/java/io/github/refurbcheck/FactoryResetPolicy.java" \
    "$refurbcheck_root/app/src/main/java/io/github/refurbcheck/ManifestRiskRules.java" \
    "$refurbcheck_root/tests/InventoryPolicyTests.java" \
    "$refurbcheck_root/tests/ManifestRiskTests.java"
"$refurbcheck_java" -classpath "$refurbcheck_classes:$refurbcheck_json_jar" io.github.refurbcheck.InventoryPolicyTests
"$refurbcheck_java" -classpath "$refurbcheck_classes:$refurbcheck_json_jar" io.github.refurbcheck.ManifestRiskTests
