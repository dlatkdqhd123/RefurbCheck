#!/usr/bin/env bash
set -euo pipefail
refurbcheck_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
for refurbcheck_suite in attestation report apk remediation malware malware_remediation inventory_policy modern_apksig catalog_update; do
    bash "$refurbcheck_root/tests/run_${refurbcheck_suite}_tests.sh"
done
mkdir -p "$refurbcheck_root/build/signal-tests"
java --module jdk.compiler/com.sun.tools.javac.Main --release 8 -encoding UTF-8 \
    -d "$refurbcheck_root/build/signal-tests" \
    "$refurbcheck_root/app/src/main/java/io/github/refurbcheck/SignalRules.java" "$refurbcheck_root/tests/SignalRulesTest.java"
java -cp "$refurbcheck_root/build/signal-tests" io.github.refurbcheck.SignalRulesTest
