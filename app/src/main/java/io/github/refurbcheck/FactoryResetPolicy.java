package io.github.refurbcheck;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

/**
 * A user's post-reset expectation, not a manufacturer-approved software list.
 * Policy results can request review, but never authorize app removal.
 */
public final class FactoryResetPolicy {
    public static final String POLICY_VERSION = "post-reset-no-personal-apps-v1";
    private FactoryResetPolicy() { }

    public static void inspect(ScanReport report, String ownPackage, boolean factoryMode) throws JSONException {
        JSONObject summary = new JSONObject().put("version", POLICY_VERSION).put("enabled", factoryMode)
                .put("approvedManufacturerBaselineAvailable", false)
                .put("automaticRemovalAuthorized", false).put("malwareClassification", false)
                .put("scope", "Current user/profile OS-reported inventory and enabled management settings");
        int unexpected = 0, systemUnknown = 0, unknown = 0;
        JSONArray candidates = new JSONArray();
        for (int i = 0; i < report.inventory.length(); i++) {
            JSONObject row = report.inventory.optJSONObject(i);
            if (row == null) { unknown++; continue; }
            JSONObject result = evaluate(row, ownPackage, factoryMode);
            row.put("factoryResetPolicy", result);
            String outcome = result.optString("outcome", "UNKNOWN");
            if ("UNEXPECTED_NON_SYSTEM".equals(outcome)) {
                unexpected++;
                candidates.put(row.optString("packageName", ""));
            } else if ("SYSTEM_BASELINE_UNVERIFIED".equals(outcome)) systemUnknown++;
            else if ("UNKNOWN".equals(outcome)) unknown++;
        }
        summary.put("unexpectedNonSystemCount", unexpected).put("systemBaselineUnverifiedCount", systemUnknown)
                .put("unknownPackageCount", unknown).put("reviewPackages", candidates)
                .put("inventoryComplete", report.inventoryComplete);
        report.evidence.put("factoryResetPolicy", summary);
        if (!factoryMode) return;

        report.add(new Finding("policy.factory_reset", "초기화 후 정책", "추가 설치 앱 확인",
                unexpected > 0 ? Finding.Status.WARN : report.inventoryComplete && unknown == 0 ? Finding.Status.INFO : Finding.Status.UNKNOWN,
                "검사 앱을 제외한 비시스템 앱 " + unexpected + "개를 초기화 후 확인 대상으로 표시했습니다. " + shortList(candidates)
                        + " 설치 출처가 스토어라고 표시되어도 자동 승인하지 않습니다.",
                "기기 설정 중 정상 자동 설치·복원된 앱도 포함될 수 있습니다. 이 표시는 사용자 기대와의 차이이며 악성코드 확정이나 자동 삭제 근거가 아닙니다. 앱 세부정보에서 출처·권한을 확인하세요."));
        report.add(new Finding("policy.oem_baseline", "초기화 후 정책", "제조사 승인 소프트웨어 기준",
                Finding.Status.UNKNOWN,
                "기기·지역·펌웨어에 맞는 제조사 인증 기준 목록이 없습니다. 시스템으로 보고된 " + systemUnknown
                        + "개 앱도 그 표시만으로 순정·승인 상태를 확정하지 않습니다.",
                "현재 기기의 첫 검사나 가져온 일반 보고서를 순정 기준으로 자동 등록하지 않습니다. 서명 이력·APK 해시 비교와 제조사 확인을 함께 사용하세요."));

        JSONObject management = report.evidence.optJSONObject("management");
        JSONArray admins = report.evidence.optJSONArray("activeDeviceAdmins");
        boolean activeObserved = admins != null && admins.length() > 0;
        boolean organizationObserved = management != null && Boolean.TRUE.equals(management.opt("organizationOwnedManagedProfile"));
        boolean readable = management != null && Boolean.TRUE.equals(management.opt("activeAdminEnumerationComplete"));
        report.add(new Finding("policy.management_expected_absent", "초기화 후 정책", "관리 앱 미등록 조건",
                activeObserved || organizationObserved ? Finding.Status.WARN : readable ? Finding.Status.INFO : Finding.Status.UNKNOWN,
                activeObserved || organizationObserved
                        ? "사용자가 관리 앱을 등록하지 않은 초기화 후 기기에서 활성 관리자 또는 조직 소유 관리 상태가 보고되었습니다."
                        : readable ? "현재 프로필에서 활성 관리자가 보고되지 않았습니다. 다른 프로필과 서버의 자동 등록 상태는 미검증입니다."
                        : "현재 프로필의 관리자 목록을 충분히 확인하지 못했습니다.",
                "기기·프로필 소유자 등록은 일반 앱에서 강제로 해제하지 않습니다. 판매자·관리 조직의 정식 등록 해제를 확인하세요. Knox 앱이 단순 설치된 상태와 실제 관리 활성 상태를 구분합니다."));

        JSONArray accessibility = report.evidence.optJSONArray("enabledAccessibilityServices");
        JSONArray notifications = report.evidence.optJSONArray("notificationListeners");
        int enabledSpecialAccess = (accessibility == null ? 0 : accessibility.length())
                + (notifications == null ? 0 : notifications.length());
        summary.put("observedSpecialAccessCount", enabledSpecialAccess);
        summary.put("activeManagementObserved", activeObserved || organizationObserved);
        if (enabledSpecialAccess > 0) report.add(new Finding("policy.special_access", "초기화 후 정책", "초기화 후 특별 접근 권한",
                Finding.Status.WARN,
                "활성 접근성 서비스·알림 접근 항목 " + enabledSpecialAccess + "개가 보고되었습니다. 초기 설정에서 허용한 보조 기능도 포함될 수 있습니다.",
                "본인이 허용하지 않았다면 설정에서 해당 권한을 끈 뒤 다시 검사하세요. 권한 존재만으로 악성 앱이나 자동 삭제 대상으로 분류하지 않습니다."));
    }

    /** Pure policy evaluator. It never changes row or remediation evidence. */
    public static JSONObject evaluate(JSONObject row, String ownPackage, boolean factoryMode) throws JSONException {
        String outcome;
        String packageName = row == null || !(row.opt("packageName") instanceof String) ? null : (String) row.opt("packageName");
        if (!factoryMode) outcome = "POLICY_DISABLED";
        else if (packageName == null || packageName.length() > 255
                || !packageName.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)*")) outcome = "UNKNOWN";
        else if (packageName.equals(ownPackage)) outcome = "EXCLUDED_SELF";
        else if (Boolean.TRUE.equals(row.opt("system"))) outcome = "SYSTEM_BASELINE_UNVERIFIED";
        else if (Boolean.FALSE.equals(row.opt("system"))) outcome = "UNEXPECTED_NON_SYSTEM";
        else outcome = "UNKNOWN";
        return new JSONObject().put("policyVersion", POLICY_VERSION).put("outcome", outcome)
                .put("automaticRemovalAuthorized", false).put("malwareClassification", false)
                .put("manufacturerApprovalVerified", false).put("action", "REVIEW_ONLY");
    }

    private static String shortList(JSONArray packages) {
        StringBuilder result = new StringBuilder();
        for (int i = 0; i < Math.min(packages.length(), 8); i++) {
            if (i > 0) result.append(", ");
            result.append(packages.optString(i, "확인 불가"));
        }
        if (packages.length() > 8) result.append(" 외 ").append(packages.length() - 8).append("개");
        return result.toString();
    }
}
