package io.github.refurbcheck;

import android.annotation.TargetApi;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.os.Build;

import org.json.JSONArray;
import org.json.JSONObject;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/** Read-only roles for currently visible active administrators. No enrollment or removal APIs. */
public final class ManagementInspection {
    private ManagementInspection() { }

    public static void inspect(Context context, ScanReport report) throws Exception {
        JSONObject evidence = new JSONObject();
        evidence.put("schema", "refurbcheck-management-v1");
        evidence.put("evidenceSource", "OS_REPORTED");
        evidence.put("scope", "Current user/profile active administrators; other profiles are not fully enumerated");
        evidence.put("allDeviceProfilesVerified", false);
        evidence.put("activeAdminEnumerationComplete", false);
        evidence.put("organizationOwnedManagedProfile", JSONObject.NULL);
        evidence.put("organizationOwnedQueryStatus", Build.VERSION.SDK_INT >= 30 ? "UNAVAILABLE" : "UNSUPPORTED_API");
        JSONArray active = new JSONArray(), roles = new JSONArray();
        evidence.put("roles", roles);
        // Keep the established field for remediation/settings links. Its
        // completeness must be read alongside management.activeAdminEnumerationComplete.
        report.evidence.put("activeDeviceAdmins", active);
        report.evidence.put("management", evidence);

        DevicePolicyManager manager = (DevicePolicyManager) context.getSystemService(Context.DEVICE_POLICY_SERVICE);
        if (manager == null) {
            evidence.put("queryError", "SERVICE_UNAVAILABLE");
            failed(report);
            return;
        }
        int unreadable = 0, ownerCount = 0;
        Map<String, JSONObject> packageRoles = new LinkedHashMap<>();
        try {
            List<ComponentName> components = manager.getActiveAdmins();
            if (components != null && components.size() > 4096) unreadable++;
            if (components != null) for (int i = 0; i < Math.min(components.size(), 4096); i++) {
                ComponentName component = components.get(i);
                if (component == null || component.getPackageName() == null) { unreadable++; continue; }
                String name = component.flattenToShortString(), pkg = component.getPackageName();
                if (name.length() > 1024 || pkg.length() > 255
                        || !pkg.matches("[A-Za-z][A-Za-z0-9_]*(\\.[A-Za-z0-9_]+)*")
                        || component.getClassName() == null || !component.getClassName().matches("[A-Za-z_.$][A-Za-z0-9_.$]*")) {
                    unreadable++;
                    continue;
                }
                active.put(name);
                JSONObject role = packageRoles.get(pkg);
                if (role == null) {
                    role = queryRoles(manager, pkg);
                    packageRoles.put(pkg, role);
                    if (!Boolean.TRUE.equals(role.opt("roleReadComplete"))) unreadable++;
                    if (Boolean.TRUE.equals(role.opt("deviceOwnerObserved")) || Boolean.TRUE.equals(role.opt("profileOwnerObserved"))) ownerCount++;
                }
                JSONObject componentRole = new JSONObject(role.toString());
                componentRole.put("component", name);
                roles.put(componentRole);
            }
            evidence.put("activeAdminEnumerationComplete", unreadable == 0);
            evidence.put("activeAdminListReadable", true);
        } catch (Exception | LinkageError error) {
            evidence.put("queryError", error.getClass().getSimpleName());
            evidence.put("activeAdminListReadable", false);
        }
        if (Build.VERSION.SDK_INT >= 30) Api30.collectOrganization(manager, evidence);
        evidence.put("unresolvedAdminEntries", unreadable);
        evidence.put("activeAdminCount", active.length());
        evidence.put("ownerPackageCount", ownerCount);

        // This annotation is also used by the post-reset policy, never as a
        // malware classification and never to authorize uninstalling an app.
        for (int i = 0; i < report.inventory.length(); i++) {
            JSONObject row = report.inventory.optJSONObject(i);
            if (row == null) continue;
            JSONObject role = packageRoles.get(row.optString("packageName", ""));
            if (role != null) row.put("managementRole", new JSONObject(role.toString()));
        }
        boolean complete = Boolean.TRUE.equals(evidence.opt("activeAdminEnumerationComplete"));
        boolean organizationOwned = Boolean.TRUE.equals(evidence.opt("organizationOwnedManagedProfile"));
        report.add(new Finding("settings.admin", "앱·설정", "활성 기기 관리자",
                active.length() > 0 ? Finding.Status.WARN : complete ? Finding.Status.INFO : Finding.Status.UNKNOWN,
                (active.length() == 0 ? "현재 프로필에서 확인한 활성 관리자 항목이 없습니다." : describe(roles))
                        + (complete ? "" : " 관리자 목록 또는 역할 정보를 일부 확인하지 못했습니다."),
                "기기 소유자·프로필 소유자는 일반 관리자보다 강한 관리 권한을 가집니다. 사용자가 등록한 관리 앱이 없는 초기화 후 기기라면 판매자에게 등록 해제를 요청하세요. 다른 프로필까지 관리자 부재를 검증한 결과는 아닙니다."));
        report.add(new Finding("settings.management_roles", "앱·설정", "기기·프로필 소유자 관리 상태",
                ownerCount > 0 || organizationOwned ? Finding.Status.WARN
                        : complete && "COLLECTED".equals(evidence.opt("organizationOwnedQueryStatus")) ? Finding.Status.INFO : Finding.Status.UNKNOWN,
                "현재 프로필의 활성 관리자 중 소유자 역할이 보고된 패키지 " + ownerCount + "개. 조직 소유 업무 프로필 상태: "
                        + (organizationOwned ? "있음으로 보고됨" : "COLLECTED".equals(evidence.opt("organizationOwnedQueryStatus")) ? "없음으로 보고됨" : "확인 불가") + ".",
                "삼성 Knox 구성 요소가 설치된 사실만으로 관리 등록으로 판정하지 않습니다. Knox Mobile Enrollment 등 서버 등록이 남으면 초기화 후 다시 등록될 수 있으며, 해당 관리 조직·판매자의 해제 절차가 필요합니다."));
    }

    private static JSONObject queryRoles(DevicePolicyManager manager, String pkg) throws Exception {
        JSONObject role = new JSONObject().put("packageName", pkg).put("activeAdminObserved", true);
        role.put("deviceOwnerObserved", JSONObject.NULL).put("profileOwnerObserved", JSONObject.NULL);
        role.put("roleReadComplete", false);
        boolean deviceKnown = false, profileKnown = false;
        try {
            role.put("deviceOwnerObserved", manager.isDeviceOwnerApp(pkg));
            deviceKnown = true;
        } catch (Exception | LinkageError error) { role.put("deviceOwnerError", error.getClass().getSimpleName()); }
        try {
            role.put("profileOwnerObserved", manager.isProfileOwnerApp(pkg));
            profileKnown = true;
        } catch (Exception | LinkageError error) { role.put("profileOwnerError", error.getClass().getSimpleName()); }
        boolean deviceOwner = Boolean.TRUE.equals(role.opt("deviceOwnerObserved"));
        boolean profileOwner = Boolean.TRUE.equals(role.opt("profileOwnerObserved"));
        role.put("roleReadComplete", deviceKnown && profileKnown);
        role.put("role", deviceOwner && profileOwner ? "DEVICE_AND_PROFILE_OWNER_REPORTED" : deviceOwner ? "DEVICE_OWNER"
                : profileOwner ? "PROFILE_OWNER" : deviceKnown && profileKnown ? "ACTIVE_ADMIN" : "UNKNOWN");
        role.put("automaticRemovalAuthorized", false);
        return role;
    }

    private static String describe(JSONArray roles) {
        StringBuilder out = new StringBuilder();
        for (int i = 0; i < Math.min(roles.length(), 12); i++) {
            JSONObject role = roles.optJSONObject(i);
            if (role == null) continue;
            if (out.length() > 0) out.append('\n');
            String kind = role.optString("role", "UNKNOWN");
            out.append(role.optString("component", "확인 불가")).append(" — ")
                    .append("DEVICE_OWNER".equals(kind) ? "기기 소유자" : "PROFILE_OWNER".equals(kind) ? "프로필 소유자"
                            : "DEVICE_AND_PROFILE_OWNER_REPORTED".equals(kind) ? "기기·프로필 소유자 보고"
                            : "ACTIVE_ADMIN".equals(kind) ? "기기 관리자" : "역할 확인 불가");
        }
        if (roles.length() > 12) out.append("\n외 ").append(roles.length() - 12).append("개 관리자 항목");
        return out.toString();
    }

    private static void failed(ScanReport report) {
        report.add(new Finding("settings.admin", "앱·설정", "활성 기기 관리자", Finding.Status.UNKNOWN,
                "기기 관리자 서비스를 조회하지 못했습니다. 관리자 없음으로 간주하지 않습니다.",
                "설정의 기기 관리자·업무 프로필 항목을 확인하세요. 조회 실패를 정상 판정으로 사용하지 않습니다."));
    }

    @TargetApi(30)
    private static final class Api30 {
        static void collectOrganization(DevicePolicyManager manager, JSONObject evidence) throws Exception {
            try {
                evidence.put("organizationOwnedManagedProfile", manager.isOrganizationOwnedDeviceWithManagedProfile());
                evidence.put("organizationOwnedQueryStatus", "COLLECTED");
            } catch (Exception | LinkageError error) {
                evidence.put("organizationOwnedQueryStatus", "ERROR");
                evidence.put("organizationOwnedQueryError", error.getClass().getSimpleName());
            }
        }
    }
}
