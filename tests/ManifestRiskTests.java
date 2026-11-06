package io.github.refurbcheck;

import org.json.JSONArray;
import org.json.JSONObject;

/** Benign metadata fixtures for false-positive controls and missing evidence. */
public final class ManifestRiskTests {
    private static int cases, assertions, failures;
    private static final String PKG = "com.example.assist", SELF = "io.github.refurbcheck";

    public static void main(String[] args) {
        test("unactivated permission declarations do not match any rule", () -> {
            JSONObject row = row(requested("REQUEST_INSTALL_PACKAGES", "READ_SMS", "RECEIVE_BOOT_COMPLETED", "QUERY_ALL_PACKAGES"), granted("READ_SMS"));
            result("NO_RULE_MATCH", 0, row, settings(false, false));
        });
        test("a normal broad package visibility permission is not a risk match", () -> result("NO_RULE_MATCH", 0,
                row(requested("QUERY_ALL_PACKAGES", "INTERNET", "RECEIVE_BOOT_COMPLETED"), granted("QUERY_ALL_PACKAGES", "INTERNET", "RECEIVE_BOOT_COMPLETED")), settings(false, false)));
        test("an active reader without extra capabilities is not a rule match", () -> result("NO_RULE_MATCH", 0,
                row(requested(), granted()), settings(true, false)));
        test("active accessibility plus declared installation requests is a review", () -> {
            JSONObject out = result("REVIEW", 1, row(requested("REQUEST_INSTALL_PACKAGES"), granted()), settings(true, false));
            equal("CAP-A11Y-INSTALL-01", out.getJSONArray("triggeredRules").getJSONObject(0).getString("ruleId"));
        });
        test("active accessibility plus granted install privilege is a review", () -> result("REVIEW", 1,
                row(requested("INSTALL_PACKAGES"), granted("INSTALL_PACKAGES")), settings(true, false)));
        test("declared signature-only install privilege without grant is not sufficient", () -> result("NO_RULE_MATCH", 0,
                row(requested("INSTALL_PACKAGES"), granted()), settings(true, false)));
        test("a declared SMS request without grant is not sufficient", () -> result("NO_RULE_MATCH", 0,
                row(requested("READ_SMS"), granted()), settings(true, false)));
        test("actual SMS or call-log grants combine with active accessibility", () -> {
            for (String permission : new String[]{"READ_SMS", "RECEIVE_SMS", "READ_CALL_LOG"})
                result("REVIEW", 1, row(requested(permission), granted(permission)), settings(true, false));
        });
        test("actual SMS grants combine with an observed active administrator", () -> {
            JSONObject out = result("REVIEW", 1, row(requested("READ_SMS"), granted("READ_SMS")), settings(false, true));
            equal("CAP-ADMIN-MESSAGES-01", out.getJSONArray("triggeredRules").getJSONObject(0).getString("ruleId"));
        });
        test("administrator alone does not match a capability rule", () -> result("NO_RULE_MATCH", 0,
                row(requested("RECEIVE_BOOT_COMPLETED"), granted("RECEIVE_BOOT_COMPLETED")), settings(false, true)));
        test("all three combinations retain separate explanations", () -> result("REVIEW", 3,
                row(requested("REQUEST_INSTALL_PACKAGES", "READ_SMS"), granted("READ_SMS")), settings(true, true)));
        test("system preloads are explicitly outside capability scoring", () -> result("SYSTEM_NOT_SCORED", 0,
                row(requested("REQUEST_INSTALL_PACKAGES", "READ_SMS"), granted("READ_SMS")).put("system", true), settings(true, true)));
        test("self is excluded by exact package name", () -> result("EXCLUDED_SELF", 0,
                row(requested("REQUEST_INSTALL_PACKAGES"), granted()).put("packageName", SELF), settings(true, false)));
        test("brand-like package names do not bypass capability checks", () -> {
            JSONObject row = row(requested("READ_SMS"), granted("READ_SMS")).put("packageName", "com.samsung.unverified");
            JSONObject settings = settings(false, false).put("enabledAccessibilityServices", new JSONArray().put("com.samsung.unverified/.Assist"));
            result("REVIEW", 1, row, settings);
        });
        test("another package with shared prefix is not an active service match", () -> {
            JSONObject settings = settings(false, false).put("enabledAccessibilityServices", new JSONArray().put(PKG + ".suffix/.Assist"));
            result("NO_RULE_MATCH", 0, row(requested("REQUEST_INSTALL_PACKAGES"), granted()), settings);
        });
        test("component matches use exact package before separator", () -> {
            for (String component : new String[]{"com.other/" + PKG, PKG + "suffix/.Assist", "." + PKG + "/.Assist"}) {
                JSONObject settings = settings(false, false).put("enabledAccessibilityServices", new JSONArray().put(component));
                JSONObject out = ManifestRiskRules.evaluate(row(requested("REQUEST_INSTALL_PACKAGES"), granted()), settings, SELF);
                equal(0, out.getJSONArray("triggeredRules").length());
            }
        });
        test("malformed component names do not create positive observations", () -> {
            for (String component : new String[]{PKG, PKG + "/", PKG + "/.Assist/Other", PKG + "/\nAssist"}) {
                JSONObject settings = settings(false, false).put("enabledAccessibilityServices", new JSONArray().put(component));
                result("UNKNOWN", 0, row(requested("REQUEST_INSTALL_PACKAGES"), granted()), settings);
            }
        });
        test("missing permission metadata is unknown", () -> result("UNKNOWN", 0,
                new JSONObject().put("packageName", PKG).put("system", false), settings(true, true)));
        test("missing settings evidence is unknown", () -> result("UNKNOWN", 0,
                row(requested("READ_SMS"), granted("READ_SMS")), new JSONObject()));
        test("null evidence is unknown", () -> result("UNKNOWN", 0,
                row(requested("READ_SMS"), granted("READ_SMS")), null));
        test("unreadable grant flags are not treated as actual grants", () -> {
            JSONObject row = row(requested("READ_SMS"), granted("READ_SMS"));
            row.getJSONObject("manifestCapabilities").put("grantFlagsComplete", false);
            result("UNKNOWN", 0, row, settings(true, true));
        });
        test("boolean evidence fields do not accept strings", () -> {
            JSONObject row = row(requested("REQUEST_INSTALL_PACKAGES", "READ_SMS"), granted("READ_SMS"));
            row.getJSONObject("manifestCapabilities").put("grantFlagsComplete", "true").put("requestedPermissionsComplete", "true");
            result("UNKNOWN", 0, row, settings(true, true));
        });
        test("known positive declaration survives unrelated grant coverage gap", () -> {
            JSONObject row = row(requested("REQUEST_INSTALL_PACKAGES"), granted());
            row.getJSONObject("manifestCapabilities").put("grantFlagsComplete", false);
            JSONObject out = result("REVIEW", 1, row, settings(true, false));
            check(!out.getBoolean("evaluationComplete"), "Partial grants were reported as complete");
        });
        test("an unrequested claimed grant is inconsistent and not scored", () -> result("UNKNOWN", 0,
                row(requested(), granted("READ_SMS")), settings(true, true)));
        test("duplicate requested permission evidence is incomplete", () -> result("UNKNOWN", 0,
                row(requested("REQUEST_INSTALL_PACKAGES", "REQUEST_INSTALL_PACKAGES"), granted()), settings(true, false)));
        test("malformed permission values are not coerced", () -> {
            for (Object invalid : new Object[]{1, JSONObject.NULL, "READ_SMS", "android.permission.READ_SMS\n"})
                result("UNKNOWN", 0, row(new JSONArray().put(invalid), granted()), settings(true, true));
        });
        test("oversized capability arrays are not analyzed as complete", () -> {
            JSONArray oversized = new JSONArray(); for (int i = 0; i < 65; i++) oversized.put("android.permission.EXAMPLE_" + i);
            result("UNKNOWN", 0, row(oversized, granted()), settings(false, false));
        });
        test("partially resolved accessibility enumeration cannot produce a clean rule result", () -> {
            JSONObject settings = settings(false, false).put("unresolvedAccessibilityServices", 1);
            result("UNKNOWN", 0, row(requested(), granted()), settings);
        });
        test("numeric accessibility coverage must be exact integer zero", () -> {
            for (Object unknown : new Object[]{"0", 0.5, -0.5, -1, JSONObject.NULL})
                result("UNKNOWN", 0, row(requested(), granted()), settings(false, false).put("unresolvedAccessibilityServices", unknown));
        });
        test("oversized active lists cannot become no-rule-match", () -> {
            JSONArray oversized = new JSONArray(); for (int i = 0; i < 4097; i++) oversized.put("com.example.other/.Service");
            result("UNKNOWN", 0, row(requested(), granted()), settings(false, false).put("enabledAccessibilityServices", oversized));
        });
        test("incomplete administrator coverage does not suppress observed combinations", () -> {
            JSONObject settings = settings(false, true);
            settings.getJSONObject("management").put("activeAdminEnumerationComplete", false);
            JSONObject out = result("REVIEW", 1, row(requested("READ_SMS"), granted("READ_SMS")), settings);
            check(!out.getBoolean("evaluationComplete"), "Admin completeness lost");
        });
        test("missing admin coverage cannot produce complete no-rule-match", () -> {
            JSONObject settings = settings(false, false); settings.remove("management");
            result("UNKNOWN", 0, row(requested(), granted()), settings);
        });
        test("evaluating a combination never changes input removal evidence", () -> {
            JSONObject row = row(requested("READ_SMS"), granted("READ_SMS")).put("remediationEligible", false).put("confirmedIoc", false);
            JSONObject settings = settings(true, true);
            String beforeRow = row.toString(), beforeSettings = settings.toString();
            result("REVIEW", 2, row, settings);
            equal(beforeRow, row.toString()); equal(beforeSettings, settings.toString());
        });
        System.out.println("ManifestRiskTests: " + (cases - failures) + "/" + cases + " scenarios passed; " + assertions + " assertions checked");
        if (failures > 0) throw new AssertionError(failures + " failures");
    }

    private static JSONObject row(JSONArray requested, JSONArray granted) {
        return new JSONObject().put("packageName", PKG).put("system", false).put("manifestCapabilities", new JSONObject()
                .put("requestedPermissionsComplete", true).put("grantFlagsComplete", true)
                .put("requestedSecurityPermissions", requested).put("grantedSecurityPermissions", granted));
    }
    private static JSONArray requested(String... names) { JSONArray out = new JSONArray(); for (String name : names) out.put("android.permission." + name); return out; }
    private static JSONArray granted(String... names) { return requested(names); }
    private static JSONObject settings(boolean accessibility, boolean admin) {
        JSONArray access = new JSONArray(), admins = new JSONArray();
        if (accessibility) access.put(PKG + "/.Assist");
        if (admin) admins.put(PKG + "/.Admin");
        return new JSONObject().put("enabledAccessibilityServices", access).put("unresolvedAccessibilityServices", 0)
                .put("activeDeviceAdmins", admins).put("management", new JSONObject().put("activeAdminEnumerationComplete", true));
    }
    private static JSONObject result(String expected, int rules, JSONObject row, JSONObject settings) throws Exception {
        JSONObject out = ManifestRiskRules.evaluate(row, settings, SELF);
        equal(expected, out.getString("outcome")); equal(rules, out.getJSONArray("triggeredRules").length());
        check(!out.getBoolean("automaticRemovalAuthorized"), "Rules authorized removal");
        check(!out.getBoolean("malwareClassification"), "Rules claimed malware");
        check(!out.getBoolean("dynamicBehaviorObserved"), "Static metadata claimed actual runtime activity");
        return out;
    }
    private interface Checked { void run() throws Exception; }
    private static void test(String name, Checked test) {
        cases++;
        try { test.run(); System.out.println("PASS " + name); }
        catch (Exception | AssertionError error) { failures++; System.err.println("FAIL " + name + ": " + error); }
    }
    private static void equal(Object expected, Object actual) { check(expected.equals(actual), "Expected " + expected + ", got " + actual); }
    private static void check(boolean value, String message) { assertions++; if (!value) throw new AssertionError(message); }
}
