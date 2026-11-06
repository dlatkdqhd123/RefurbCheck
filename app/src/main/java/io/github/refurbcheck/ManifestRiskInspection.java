package io.github.refurbcheck;

import android.content.pm.PackageInfo;
import android.content.pm.ServiceInfo;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;

/** Collects OS-reported manifest capabilities and explains observed active combinations. */
public final class ManifestRiskInspection {
    private static final int MAX_DECLARATIONS = 4096, MAX_SERVICES = 512;
    private static final Set<String> PERMISSIONS = new HashSet<>(Arrays.asList(
            "android.permission.READ_SMS", "android.permission.RECEIVE_SMS", "android.permission.SEND_SMS",
            "android.permission.READ_CALL_LOG", "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
            "android.permission.READ_CONTACTS", "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION",
            "android.permission.RECEIVE_BOOT_COMPLETED", "android.permission.REQUEST_INSTALL_PACKAGES",
            "android.permission.INSTALL_PACKAGES", "android.permission.QUERY_ALL_PACKAGES", "android.permission.SYSTEM_ALERT_WINDOW",
            "android.permission.MANAGE_EXTERNAL_STORAGE", "android.permission.INTERNET"));
    private ManifestRiskInspection() { }

    /** Caller must query PackageInfo with GET_PERMISSIONS | GET_SERVICES. */
    public static void collectDeclared(PackageInfo info, JSONObject row) throws JSONException {
        JSONObject out = new JSONObject().put("schema", "refurbcheck-manifest-capabilities-v1")
                .put("evidenceSource", "OS_REPORTED_MANIFEST_METADATA")
                .put("independentManifestParse", false).put("servicesQueryRequested", true);
        JSONArray requested = new JSONArray(), granted = new JSONArray(), serviceRoles = new JSONArray();
        boolean complete = true;
        String[] names = info.requestedPermissions;
        int[] flags = info.requestedPermissionsFlags;
        boolean flagsComplete = names == null || names.length == 0 || flags != null && flags.length == names.length;
        if (names != null) {
            if (names.length > MAX_DECLARATIONS) { complete = false; flagsComplete = false; }
            Set<String> seen = new HashSet<>();
            for (int i = 0; i < Math.min(names.length, MAX_DECLARATIONS); i++) {
                String name = names[i];
                if (name == null || name.length() > 512 || !seen.add(name)) { complete = false; continue; }
                if (!PERMISSIONS.contains(name)) continue;
                requested.put(name);
                if (flags != null && i < flags.length && (flags[i] & PackageInfo.REQUESTED_PERMISSION_GRANTED) != 0) granted.put(name);
            }
        }
        out.put("requestedSecurityPermissions", requested).put("grantedSecurityPermissions", granted)
                .put("requestedPermissionsComplete", complete).put("grantFlagsComplete", complete && flagsComplete);
        ServiceInfo[] services = info.services;
        boolean servicesComplete = services == null || services.length <= MAX_SERVICES;
        if (services != null) for (int i = 0; i < Math.min(services.length, MAX_SERVICES); i++) {
            ServiceInfo service = services[i];
            if (service == null) { servicesComplete = false; continue; }
            String role = serviceRole(service.permission);
            if (role == null) continue;
            if (!safeIdentifier(service.name, 512) || !safeIdentifier(service.packageName, 255)) { servicesComplete = false; continue; }
            serviceRoles.put(new JSONObject().put("role", role).put("serviceName", service.name).put("packageName", service.packageName)
                    .put("requiredCallerPermission", service.permission).put("exported", service.exported).put("enabled", service.enabled));
        }
        out.put("declaredServiceRoles", serviceRoles).put("servicesReadComplete", servicesComplete)
                .put("declaredServiceCount", services == null ? 0 : services.length);
        row.put("manifestCapabilities", out);
    }

    public static void inspect(ScanReport report, String ownPackage) throws JSONException {
        int reviewed = 0, unavailable = 0, excludedSystem = 0, matchedPackages = 0, matchedRules = 0;
        JSONArray matches = new JSONArray(); StringBuilder details = new StringBuilder();
        for (int i = 0; i < report.inventory.length(); i++) {
            JSONObject row = report.inventory.optJSONObject(i);
            if (row == null) { unavailable++; continue; }
            JSONObject result = ManifestRiskRules.evaluate(row, report.evidence, ownPackage);
            row.put("capabilityRiskReview", result);
            String outcome = result.optString("outcome", "UNKNOWN");
            if ("EXCLUDED_SELF".equals(outcome)) continue;
            if ("SYSTEM_NOT_SCORED".equals(outcome)) { excludedSystem++; continue; }
            reviewed++;
            if (!Boolean.TRUE.equals(result.opt("evaluationComplete"))) unavailable++;
            JSONArray rules = result.optJSONArray("triggeredRules");
            if (rules == null || rules.length() == 0) continue;
            matchedPackages++; matchedRules += rules.length();
            String pkg = row.optString("packageName", "");
            matches.put(new JSONObject().put("packageName", pkg).put("rules", rules));
            if (details.length() < 6000) {
                if (details.length() > 0) details.append('\n');
                details.append(pkg);
                for (int j = 0; j < rules.length(); j++) {
                    JSONObject rule = rules.optJSONObject(j);
                    if (rule != null) details.append("\n  ").append(rule.optString("ruleId", "")).append(": ").append(rule.optString("title", ""));
                }
            }
        }
        JSONObject evidence = new JSONObject().put("rulesVersion", ManifestRiskRules.VERSION).put("scope", "Non-system apps visible in current user/profile")
                .put("reviewedPackageCount", reviewed).put("systemPackagesNotScored", excludedSystem).put("incompletePackageCount", unavailable)
                .put("matchedPackageCount", matchedPackages).put("matchedRuleCount", matchedRules).put("matches", matches)
                .put("malwareClassification", false).put("automaticRemovalAuthorized", false).put("dynamicBehaviorObserved", false);
        report.evidence.put("capabilityRiskReview", evidence);
        report.add(new Finding("apps.capability_combinations", "앱·설정", "활성 권한 조합 확인",
                matchedPackages > 0 ? Finding.Status.WARN : unavailable > 0 || !report.inventoryComplete ? Finding.Status.UNKNOWN : Finding.Status.INFO,
                "비시스템 앱 " + reviewed + "개를 제한된 규칙으로 점검했습니다. 확인이 필요한 조합 " + matchedRules + "건 (" + matchedPackages
                        + "개 앱), 자료 일부 미확인 " + unavailable + "개. " + (details.length() > 0 ? "\n" + details : "일치 없음도 신규 악성코드 부재를 증명하지 않습니다."),
                "실제로 활성화된 접근성·관리자와 설치 요청·문자/통화기록 권한이 함께 있는지 확인합니다. 정상 관리·자동화 앱도 해당할 수 있습니다. 실행 동작·DEX 코드를 분석한 결과가 아니며 자동 삭제 근거로 사용하지 않습니다."));
    }

    private static String serviceRole(String permission) {
        if ("android.permission.BIND_ACCESSIBILITY_SERVICE".equals(permission)) return "ACCESSIBILITY_SERVICE";
        if ("android.permission.BIND_NOTIFICATION_LISTENER_SERVICE".equals(permission)) return "NOTIFICATION_LISTENER";
        if ("android.permission.BIND_VPN_SERVICE".equals(permission)) return "VPN_SERVICE";
        return null;
    }
    private static boolean safeIdentifier(String value, int limit) {
        return value != null && value.length() > 0 && value.length() <= limit && value.matches("[A-Za-z_.$][A-Za-z0-9_.$]*");
    }
}
