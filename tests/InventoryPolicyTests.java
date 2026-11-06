package io.github.refurbcheck;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.Arrays;

/** Benign synthetic metadata only: no malicious APKs or destructive actions. */
public final class InventoryPolicyTests {
    private static int cases, assertions, failures;
    private static final String A = digest('a'), B = digest('b'), C = digest('c'), D = digest('d');

    public static void main(String[] args) {
        test("same current signer is a set comparison", () -> relation(SignatureLineage.Relation.SAME_SIGNERS, signed(A), signed(A)));
        test("multisigner ordering is irrelevant", () -> relation(SignatureLineage.Relation.SAME_SIGNERS, multi(A, B), multi(B, A)));
        test("sharing one of several signers is not an identity match", () -> relation(SignatureLineage.Relation.DIFFERENT_SIGNERS, multi(A, B), multi(A, C)));
        test("removing a signer is not a rotation", () -> relation(SignatureLineage.Relation.DIFFERENT_SIGNERS, multi(A, B), single(A, A)));
        test("adding a signer is not a rotation", () -> relation(SignatureLineage.Relation.DIFFERENT_SIGNERS, single(A, A), multi(A, B)));
        test("legacy inventory can compare current sets", () -> relation(SignatureLineage.Relation.SAME_SIGNERS, signed(A), signed(A).put("signingMode", "LEGACY")));
        test("a different certificate without rotation evidence is different", () -> relation(SignatureLineage.Relation.DIFFERENT_SIGNERS, signed(A), signed(B)));
        test("new OS-reported lineage connects to an older inventory", () -> relation(SignatureLineage.Relation.FORWARD_ROTATION_REPORTED, signed(A), single(B, A, B)));
        test("successive rotations extend the ordered prefix", () -> relation(SignatureLineage.Relation.FORWARD_ROTATION_REPORTED, single(B, A, B), single(D, A, B, C, D)));
        test("previous key direction is not a new key rotation", () -> relation(SignatureLineage.Relation.BACKWARD_ROTATION_REPORTED, single(C, A, B, C), single(B, A, B)));
        test("a fork from the same ancestor is not forward-compatible", () -> relation(SignatureLineage.Relation.DIFFERENT_SIGNERS, single(B, A, B), single(C, A, C)));
        test("matching old key in a contradictory prefix is not accepted", () -> relation(SignatureLineage.Relation.CONFLICTING_LINEAGE_REPORTED, single(B, A, B), single(C, D, B, C)));
        test("reverse contradictory prefix is not accepted", () -> relation(SignatureLineage.Relation.CONFLICTING_LINEAGE_REPORTED, single(C, D, B, C), single(B, A, B)));
        test("missing prefix is not silently treated as identical", () -> relation(SignatureLineage.Relation.CONFLICTING_LINEAGE_REPORTED, single(B, B), single(C, A, B, C)));
        test("malformed explicit previous history prevents compatibility", () -> relation(SignatureLineage.Relation.CONFLICTING_LINEAGE_REPORTED,
                single(A, B), single(C, A, C)));
        test("history must end at the current signer", () -> relation(SignatureLineage.Relation.DIFFERENT_SIGNERS, signed(A), single(C, A, B)));
        test("duplicate history entries are rejected", () -> relation(SignatureLineage.Relation.DIFFERENT_SIGNERS, signed(A), single(B, A, A, B)));
        test("history with repeated hashes in different case is rejected", () -> relation(SignatureLineage.Relation.DIFFERENT_SIGNERS, signed(A), single(B, A, A.toUpperCase(java.util.Locale.ROOT), B)));
        test("unreadable history is not used", () -> relation(SignatureLineage.Relation.DIFFERENT_SIGNERS, signed(A), single(B, A, B).put("signingHistoryReadable", false)));
        test("string true is not accepted as readable history", () -> relation(SignatureLineage.Relation.DIFFERENT_SIGNERS, signed(A), single(B, A, B).put("signingHistoryReadable", "true")));
        test("a multi-signer declaration cannot smuggle a lineage", () -> relation(SignatureLineage.Relation.DIFFERENT_SIGNERS, multi(A, C), multi(B, C)
                .put("signingHistoryReadable", true).put("signingHistorySha256", array(A, B))));
        test("mode and current signer count must agree", () -> {
            relation(SignatureLineage.Relation.UNKNOWN, signed(A), signed(B).put("signingMode", "MULTIPLE"));
            relation(SignatureLineage.Relation.UNKNOWN, signed(A), signed(B, C).put("signingMode", "SINGLE"));
        });
        test("unrecognized current mode is unknown", () -> relation(SignatureLineage.Relation.UNKNOWN, signed(A), signed(B).put("signingMode", "UNKNOWN")));
        test("JSON null or non-string modes are not coerced", () -> {
            relation(SignatureLineage.Relation.UNKNOWN, signed(A), signed(B).put("signingMode", JSONObject.NULL));
            relation(SignatureLineage.Relation.UNKNOWN, signed(A), signed(B).put("signingMode", 1));
        });
        test("unreadable and string readable flags stay unknown", () -> {
            relation(SignatureLineage.Relation.UNKNOWN, signed(A), signed(A).put("signingReadable", false));
            relation(SignatureLineage.Relation.UNKNOWN, signed(A), signed(A).put("signingReadable", "true"));
        });
        test("malformed current certificate digests stay unknown", () -> {
            for (Object bad : new Object[]{"", A.substring(1), digest('g'), 123, JSONObject.NULL})
                relation(SignatureLineage.Relation.UNKNOWN, signed(A), signed(A).put("signingSha256", new JSONArray().put(bad)));
        });
        test("missing duplicate and oversized signer lists stay unknown", () -> {
            relation(SignatureLineage.Relation.UNKNOWN, signed(A), signed());
            relation(SignatureLineage.Relation.UNKNOWN, signed(A), signed(A, A));
            JSONArray many = new JSONArray(); for (int i = 0; i < 33; i++) many.put(String.format(java.util.Locale.ROOT, "%064x", i));
            relation(SignatureLineage.Relation.UNKNOWN, signed(A), signed(A).put("signingSha256", many));
            JSONObject missing = signed(A); missing.remove("signingSha256");
            relation(SignatureLineage.Relation.UNKNOWN, signed(A), missing);
        });
        test("digest letter case normalizes without modifying inputs", () -> {
            JSONObject old = signed(A.toUpperCase(java.util.Locale.ROOT)), now = single(B, A, B);
            String beforeOld = old.toString(), beforeNow = now.toString();
            relation(SignatureLineage.Relation.FORWARD_ROTATION_REPORTED, old, now);
            equal(beforeOld, old.toString()); equal(beforeNow, now.toString());
        });
        test("baseline labels reported forward rotation without trust promotion", () -> {
            String text = BaselineComparator.compare(report(signed(A)), report(single(B, A, B)));
            contains(text, "서명 교체 이력 연결 (자기 보고)"); contains(text, "서명 교체 이력 연결 1건");
            contains(text, "보고서 진위·APK 서명·앱 안전성을 인증하지 않습니다");
            check(!text.contains("서명 차이: com.example.app"), "Forward lineage was reported as unrelated signer");
        });
        test("baseline keeps inverse changes separate", () -> {
            String text = BaselineComparator.compare(report(single(B, A, B)), report(single(A, A)));
            contains(text, "이전 키 방향 변경 1건"); contains(text, "서명 이력상 이전 키로 변경");
        });
        test("baseline keeps conflicting history separate", () -> {
            String text = BaselineComparator.compare(report(single(B, A, B)), report(single(C, D, B, C)));
            contains(text, "서명 이력 모순 1건"); contains(text, "정상 교체로 분류하지 않습니다");
        });

        test("known installer does not approve a third-party app", () -> {
            JSONObject row = signed(A).put("installer", "com.android.vending").put("installerReadable", true);
            outcome("UNEXPECTED_NON_SYSTEM", row, true);
        });
        test("missing installer does not become malware", () -> outcome("UNEXPECTED_NON_SYSTEM", signed(A), true));
        test("Samsung-looking package names are not trusted allowlists", () -> {
            outcome("UNEXPECTED_NON_SYSTEM", signed(A).put("packageName", "com.samsung.fake"), true);
            outcome("UNEXPECTED_NON_SYSTEM", signed(A).put("packageName", "com.google.fake"), true);
        });
        test("system classification does not authenticate original firmware", () -> {
            JSONObject result = outcome("SYSTEM_BASELINE_UNVERIFIED", signed(A).put("system", true), true);
            check(!result.getBoolean("manufacturerApprovalVerified"), "System flag promoted to manufacturer trust");
        });
        test("application itself is excluded by exact identity only", () -> {
            outcome("EXCLUDED_SELF", signed(A).put("packageName", "io.github.refurbcheck"), true);
            outcome("UNEXPECTED_NON_SYSTEM", signed(A).put("packageName", "io.github.refurbcheck.other"), true);
        });
        test("disabled policy does not review software", () -> outcome("POLICY_DISABLED", signed(A), false));
        test("missing and malformed package identity stays unknown", () -> {
            for (Object bad : new Object[]{"", "bad name", ".bad", "com.example.\n", 1, JSONObject.NULL})
                outcome("UNKNOWN", signed(A).put("packageName", bad), true);
            outcome("UNKNOWN", null, true);
        });
        test("system booleans are strict", () -> {
            for (Object bad : new Object[]{"true", "false", 0, JSONObject.NULL}) outcome("UNKNOWN", signed(A).put("system", bad), true);
        });
        test("policy evaluation never overwrites existing remediation evidence", () -> {
            JSONObject row = signed(A).put("remediationEligible", true).put("confirmedIoc", true);
            String before = row.toString(); outcome("UNEXPECTED_NON_SYSTEM", row, true); equal(before, row.toString());
        });
        test("inventory policy warnings do not create remediation authorization", () -> {
            ScanReport report = inventory(signed(A), signed(B).put("packageName", "com.vendor.preload").put("system", true));
            FactoryResetPolicy.inspect(report, "io.github.refurbcheck", true);
            JSONObject summary = report.evidence.getJSONObject("factoryResetPolicy");
            equal(1, summary.getInt("unexpectedNonSystemCount")); equal(1, summary.getInt("systemBaselineUnverifiedCount"));
            equal(Finding.Status.WARN, finding(report, "policy.factory_reset").status);
            equal(Finding.Status.UNKNOWN, finding(report, "policy.oem_baseline").status);
            equal(Finding.Status.UNKNOWN, finding(report, "policy.management_expected_absent").status);
            for (int i = 0; i < report.inventory.length(); i++) {
                JSONObject row = report.inventory.getJSONObject(i);
                check(!row.has("remediationEligible"), "Policy created removal eligibility");
                check(!row.has("confirmedIoc"), "Policy created an IOC confirmation");
                check(!row.getJSONObject("factoryResetPolicy").getBoolean("automaticRemovalAuthorized"), "Policy authorized removal");
            }
        });
        test("policy does not mutate existing scan action evidence", () -> {
            JSONObject row = signed(A).put("remediationEligible", true).put("confirmedIoc", true);
            ScanReport report = inventory(row); FactoryResetPolicy.inspect(report, "io.github.refurbcheck", true);
            check(row.getBoolean("remediationEligible"), "Policy overwrote prior removal evidence");
            check(row.getBoolean("confirmedIoc"), "Policy overwrote a prior IOC observation");
        });
        test("an incomplete empty inventory does not satisfy no-extra-apps policy", () -> {
            ScanReport report = new ScanReport(); FactoryResetPolicy.inspect(report, "io.github.refurbcheck", true);
            equal(Finding.Status.UNKNOWN, finding(report, "policy.factory_reset").status);
        });
        test("known current-profile admin remains a policy warning", () -> {
            ScanReport report = inventory();
            report.evidence.put("activeDeviceAdmins", array("com.vendor.admin/.Receiver"));
            report.evidence.put("management", new JSONObject().put("activeAdminEnumerationComplete", true));
            FactoryResetPolicy.inspect(report, "io.github.refurbcheck", true);
            equal(Finding.Status.WARN, finding(report, "policy.management_expected_absent").status);
        });
        test("organization-owned observation warns even with no visible admin", () -> {
            ScanReport report = inventory();
            report.evidence.put("activeDeviceAdmins", new JSONArray());
            report.evidence.put("management", new JSONObject().put("activeAdminEnumerationComplete", true).put("organizationOwnedManagedProfile", true));
            FactoryResetPolicy.inspect(report, "io.github.refurbcheck", true);
            equal(Finding.Status.WARN, finding(report, "policy.management_expected_absent").status);
        });
        test("preloaded Knox-looking app alone is not active management", () -> {
            ScanReport report = inventory(signed(A).put("packageName", "com.samsung.knox.example").put("system", true));
            report.evidence.put("activeDeviceAdmins", new JSONArray());
            report.evidence.put("management", new JSONObject().put("activeAdminEnumerationComplete", true).put("organizationOwnedManagedProfile", false));
            FactoryResetPolicy.inspect(report, "io.github.refurbcheck", true);
            equal(Finding.Status.INFO, finding(report, "policy.management_expected_absent").status);
            equal(Finding.Status.INFO, finding(report, "policy.factory_reset").status);
        });
        test("special-access activation is a policy warning, not malware", () -> {
            ScanReport report = inventory();
            report.evidence.put("enabledAccessibilityServices", array("com.normal.access/.Reader"));
            report.evidence.put("notificationListeners", array("com.normal.watch/.Notifications"));
            FactoryResetPolicy.inspect(report, "io.github.refurbcheck", true);
            equal(2, report.evidence.getJSONObject("factoryResetPolicy").getInt("observedSpecialAccessCount"));
            equal(Finding.Status.WARN, finding(report, "policy.special_access").status);
            contains(finding(report, "policy.special_access").action, "자동 삭제 대상으로 분류하지 않습니다");
        });
        test("disabled policy records its status without adding warnings", () -> {
            ScanReport report = inventory(signed(A)); FactoryResetPolicy.inspect(report, "io.github.refurbcheck", false);
            equal(0, report.findings.size());
            equal("POLICY_DISABLED", report.inventory.getJSONObject(0).getJSONObject("factoryResetPolicy").getString("outcome"));
        });
        System.out.println("InventoryPolicyTests: " + (cases - failures) + "/" + cases + " scenarios passed; " + assertions + " assertions checked");
        if (failures != 0) throw new AssertionError(failures + " failures");
    }

    private static JSONObject signed(String... signers) {
        return new JSONObject().put("packageName", "com.example.app").put("system", false)
                .put("versionCode", 1).put("versionName", "1").put("signingReadable", true).put("signingSha256", array(signers));
    }
    private static JSONObject single(String current, String... history) {
        return signed(current).put("signingMode", "SINGLE").put("signingHistoryReadable", true).put("signingHistorySha256", array(history));
    }
    private static JSONObject multi(String... current) {
        return signed(current).put("signingMode", "MULTIPLE").put("signingHistoryReadable", false).put("signingHistorySha256", new JSONArray());
    }
    private static JSONArray array(String... values) { return new JSONArray(Arrays.asList(values)); }
    private static String digest(char value) { char[] bytes = new char[64]; Arrays.fill(bytes, value); return new String(bytes); }
    private static void relation(SignatureLineage.Relation expected, JSONObject old, JSONObject now) { equal(expected, SignatureLineage.compare(old, now)); }
    private static JSONObject outcome(String expected, JSONObject row, boolean enabled) throws Exception {
        JSONObject result = FactoryResetPolicy.evaluate(row, "io.github.refurbcheck", enabled);
        equal(expected, result.getString("outcome"));
        check(!result.getBoolean("automaticRemovalAuthorized"), "Unexpected removal authorization");
        check(!result.getBoolean("malwareClassification"), "Policy was classified as malware");
        return result;
    }
    private static ScanReport inventory(JSONObject... rows) {
        ScanReport report = new ScanReport(); report.inventoryComplete = true;
        for (JSONObject row : rows) report.inventory.put(row);
        return report;
    }
    private static JSONObject report(JSONObject row) {
        return new JSONObject().put("schema", "refurbcheck-report-v2").put("inventoryComplete", true)
                .put("inventory", new JSONArray().put(row)).put("evidence", new JSONObject().put("device", new JSONObject()
                        .put("manufacturer", "Samsung").put("brand", "Samsung").put("model", "Synthetic Model")
                        .put("device", "synthetic").put("product", "synthetic").put("fingerprint", "test/reference")));
    }
    private static Finding finding(ScanReport report, String id) {
        for (Finding finding : report.findings) if (id.equals(finding.id)) return finding;
        throw new AssertionError("Missing finding " + id);
    }
    private interface Checked { void run() throws Exception; }
    private static void test(String name, Checked test) {
        cases++;
        try { test.run(); System.out.println("PASS " + name); }
        catch (Exception | AssertionError error) { failures++; System.err.println("FAIL " + name + ": " + error); }
    }
    private static void equal(Object expected, Object actual) { check(expected.equals(actual), "Expected " + expected + ", got " + actual); }
    private static void contains(String actual, String expected) { check(actual.contains(expected), "Missing " + expected); }
    private static void check(boolean value, String message) { assertions++; if (!value) throw new AssertionError(message); }
}
