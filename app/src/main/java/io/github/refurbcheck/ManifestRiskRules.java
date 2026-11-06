package io.github.refurbcheck;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.util.HashSet;
import java.util.Set;

/** Explainable capability combinations. These rules cannot declare malware or authorize removal. */
public final class ManifestRiskRules {
    public static final String VERSION = "active-capability-combinations-1";
    private static final String PREFIX = "android.permission.";
    private ManifestRiskRules() { }

    public static JSONObject evaluate(JSONObject row, JSONObject evidence, String ownPackage) throws JSONException {
        JSONObject out = new JSONObject().put("rulesVersion", VERSION).put("evidenceSource", "OS_REPORTED")
                .put("malwareClassification", false).put("automaticRemovalAuthorized", false)
                .put("dynamicBehaviorObserved", false).put("evaluationComplete", false);
        JSONArray triggered = new JSONArray(); out.put("triggeredRules", triggered);
        String pkg = row != null && row.opt("packageName") instanceof String ? (String) row.opt("packageName") : "";
        if (pkg.length() == 0 || pkg.length() > 255 || !pkg.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)*"))
            return out.put("outcome", "UNKNOWN");
        if (pkg.equals(ownPackage)) return out.put("outcome", "EXCLUDED_SELF");
        // System metadata is not a trust proof. Avoid noisy generic capability
        // scoring for preloads; APK hashes, signatures and baseline checks still
        // inspect them. This exclusion is explicit in every report.
        if (Boolean.TRUE.equals(row.opt("system"))) return out.put("outcome", "SYSTEM_NOT_SCORED");
        if (!Boolean.FALSE.equals(row.opt("system"))) return out.put("outcome", "UNKNOWN");
        JSONObject caps = row.optJSONObject("manifestCapabilities");
        if (caps == null || evidence == null) return out.put("outcome", "UNKNOWN");
        Set<String> requested = Boolean.TRUE.equals(caps.opt("requestedPermissionsComplete"))
                ? permissions(caps.opt("requestedSecurityPermissions")) : null;
        Set<String> granted = Boolean.TRUE.equals(caps.opt("grantFlagsComplete"))
                ? permissions(caps.opt("grantedSecurityPermissions")) : null;
        if (granted != null && (requested == null || !requested.containsAll(granted))) granted = null;
        JSONArray accessibility = evidence.optJSONArray("enabledAccessibilityServices");
        JSONArray admins = evidence.optJSONArray("activeDeviceAdmins");
        boolean activeAccessibility = containsComponent(accessibility, pkg), activeAdmin = containsComponent(admins, pkg);
        out.put("activeAccessibilityObserved", activeAccessibility).put("activeAdminObserved", activeAdmin);
        out.put("requestedCapabilitiesReadable", requested != null).put("grantedCapabilitiesReadable", granted != null);
        boolean canRequestInstall = has(requested, "REQUEST_INSTALL_PACKAGES") || has(granted, "INSTALL_PACKAGES");
        boolean messageAccess = has(granted, "READ_SMS") || has(granted, "RECEIVE_SMS") || has(granted, "READ_CALL_LOG");
        if (activeAccessibility && canRequestInstall)
            rule(triggered, "CAP-A11Y-INSTALL-01", "활성 접근성과 앱 설치 요청 기능",
                    "활성 접근성 서비스", "REQUEST_INSTALL_PACKAGES 선언 또는 INSTALL_PACKAGES 권한 부여",
                    "화면 조작 권한과 설치 요청 기능이 함께 보고되었습니다. 정상 자동화·보조 앱도 해당할 수 있으며, 실제 설치·악성 동작을 관측한 결과는 아닙니다.");
        if (activeAccessibility && messageAccess)
            rule(triggered, "CAP-A11Y-MESSAGES-01", "활성 접근성과 문자·통화기록 접근",
                    "활성 접근성 서비스", "READ_SMS/RECEIVE_SMS/READ_CALL_LOG 중 하나 이상 실제 부여",
                    "화면 접근 권한과 문자·통화기록 읽기 권한이 함께 보고되었습니다. 이 조합의 필요성과 사용자가 허용한 앱인지 확인하세요.");
        if (activeAdmin && messageAccess)
            rule(triggered, "CAP-ADMIN-MESSAGES-01", "활성 관리자와 문자·통화기록 접근",
                    "활성 기기 관리자", "READ_SMS/RECEIVE_SMS/READ_CALL_LOG 중 하나 이상 실제 부여",
                    "기기 관리 권한과 문자·통화기록 접근이 함께 보고되었습니다. 회사 관리·분실 방지 앱일 수도 있으므로 관리 등록 출처를 확인하세요.");
        JSONObject management = evidence.optJSONObject("management");
        boolean managementComplete = management != null && Boolean.TRUE.equals(management.opt("activeAdminEnumerationComplete"));
        Object unresolved = evidence.opt("unresolvedAccessibilityServices");
        boolean accessibilityComplete = componentListComplete(accessibility)
                && (unresolved instanceof Integer || unresolved instanceof Long) && ((Number) unresolved).longValue() == 0;
        boolean complete = requested != null && granted != null && accessibilityComplete && componentListComplete(admins) && managementComplete;
        out.put("evaluationComplete", complete);
        return out.put("outcome", triggered.length() > 0 ? "REVIEW" : complete ? "NO_RULE_MATCH" : "UNKNOWN");
    }

    private static void rule(JSONArray results, String id, String title, String first, String second, String interpretation) throws JSONException {
        results.put(new JSONObject().put("ruleId", id).put("title", title)
                .put("observations", new JSONArray().put(first).put(second)).put("interpretation", interpretation));
    }
    private static boolean has(Set<String> values, String permission) { return values != null && values.contains(PREFIX + permission); }

    private static Set<String> permissions(Object raw) {
        if (!(raw instanceof JSONArray)) return null;
        JSONArray values = (JSONArray) raw;
        if (values.length() > 64) return null;
        Set<String> result = new HashSet<>();
        for (int i = 0; i < values.length(); i++) {
            Object value = values.opt(i);
            if (!(value instanceof String) || ((String) value).length() > 200
                    || !((String) value).matches("android\\.permission\\.[A-Z0-9_]+") || !result.add((String) value)) return null;
        }
        return result;
    }

    private static boolean containsComponent(JSONArray values, String pkg) {
        if (values == null || values.length() > 4096) return false;
        for (int i = 0; i < values.length(); i++) {
            Object value = values.opt(i);
            if (!(value instanceof String)) continue;
            String component = (String) value;
            if (component.length() > 1024) continue;
            int slash = component.indexOf('/');
            if (slash < 1 || slash == component.length() - 1 || !pkg.equals(component.substring(0, slash))) continue;
            String name = component.substring(slash + 1);
            if (name.matches("[A-Za-z_.$][A-Za-z0-9_.$]*")) return true;
        }
        return false;
    }

    private static boolean componentListComplete(JSONArray values) {
        if (values == null || values.length() > 4096) return false;
        for (int i = 0; i < values.length(); i++) {
            Object value = values.opt(i);
            if (!(value instanceof String) || ((String) value).length() > 1024) return false;
            String component = (String) value;
            int slash = component.indexOf('/');
            if (slash < 1 || slash == component.length() - 1
                    || !component.substring(0, slash).matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)*")
                    || !component.substring(slash + 1).matches("[A-Za-z_.$][A-Za-z0-9_.$]*")) return false;
        }
        return true;
    }
}
