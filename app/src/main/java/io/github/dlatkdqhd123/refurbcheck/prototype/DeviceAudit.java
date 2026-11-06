package io.github.dlatkdqhd123.refurbcheck.prototype;

import android.accessibilityservice.AccessibilityServiceInfo;
import android.app.KeyguardManager;
import android.app.admin.DevicePolicyManager;
import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.ResolveInfo;
import android.os.Build;
import android.view.accessibility.AccessibilityManager;
import java.time.LocalDate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Comparator;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

public final class DeviceAudit {
    public static final class Check {
        public final String title, action;
        public final AuditRules.Result result;
        Check(String title, AuditRules.Status status, String detail, String action) {
            this(title, new AuditRules.Result(status, detail), action);
        }
        Check(String title, AuditRules.Result result, String action) {
            this.title = title; this.result = result; this.action = action;
        }
    }
    public static final class App {
        public String name, pkg, source;
        public boolean system;
        public final List<String> notes = new ArrayList<>();
        public final List<String> grants = new ArrayList<>();
    }
    public final List<Check> checks = new ArrayList<>();
    public final List<App> apps = new ArrayList<>();
    public int appReadFailures;
    public boolean appsComplete;
    public final String timestamp = java.time.ZonedDateTime.now().toString();
    private DeviceAudit() {}
    public static DeviceAudit run(Context context) {
        DeviceAudit audit = new DeviceAudit();
        audit.checks.add(new Check("기기 / OS 표시", AuditRules.Status.OBSERVED,
                Build.MANUFACTURER + " " + Build.MODEL + " · Android " + Build.VERSION.RELEASE
                + " (API " + Build.VERSION.SDK_INT + ")\n제조사·OS 자체 보고값입니다. 정품·리퍼 이력이나 부품 변조를 증명하지 않습니다.", null));
        audit.checks.add(new Check("보안 패치", AuditRules.patch(Build.VERSION.SECURITY_PATCH, LocalDate.now()), "update"));
        try {
            KeyguardManager lock = context.getSystemService(KeyguardManager.class);
            if (lock == null) throw new IllegalStateException();
            boolean secure = lock.isDeviceSecure();
            audit.checks.add(new Check("화면 잠금", secure ? AuditRules.Status.OBSERVED : AuditRules.Status.REVIEW,
                    secure ? "현재 사용자에게 PIN·패턴·비밀번호 잠금이 설정되어 있습니다. 잠금 강도나 유출 여부는 판단하지 않습니다."
                           : "현재 사용자에게 보안 화면 잠금이 없습니다. PIN·비밀번호 등을 설정하세요.", "security"));
        } catch (RuntimeException error) { audit.unavailable("화면 잠금", "security"); }
        try {
            DevicePolicyManager policy = context.getSystemService(DevicePolicyManager.class);
            if (policy == null) throw new IllegalStateException();
            int status = policy.getStorageEncryptionStatus();
            boolean active = status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE
                    || status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_PER_USER;
            String detail;
            AuditRules.Status level;
            if (active) { level = AuditRules.Status.OBSERVED; detail = "시스템이 저장소 암호화 활성 상태를 보고했습니다."; }
            else if (status == DevicePolicyManager.ENCRYPTION_STATUS_INACTIVE || status == DevicePolicyManager.ENCRYPTION_STATUS_ACTIVE_DEFAULT_KEY) {
                level = AuditRules.Status.REVIEW; detail = "암호화 비활성 또는 기본 키 상태를 보고했습니다. 화면 잠금·보안 설정을 확인하세요.";
            } else { level = AuditRules.Status.UNKNOWN; detail = "암호화 상태를 확정할 수 없습니다 (상태 코드 " + status + ")."; }
            audit.checks.add(new Check("저장소 암호화", level, detail + " 데이터 복구 저항성이나 하드웨어 무결성 검증은 아닙니다.", "security"));
        } catch (RuntimeException error) { audit.unavailable("저장소 암호화", "security"); }
        boolean unusual = !"user".equals(Build.TYPE) || (Build.TAGS != null && Build.TAGS.contains("test-keys"));
        audit.checks.add(new Check("OS 빌드 신호", unusual ? AuditRules.Status.REVIEW : AuditRules.Status.OBSERVED,
                "type=" + Build.TYPE + " · tags=" + Build.TAGS + "\n"
                + (unusual ? "일반 상용 빌드와 다른 신호입니다. 개발·커스텀 OS일 수도 있으며 감염 증거는 아닙니다."
                           : "일반 상용 빌드 형태입니다. 이 값만으로 순정 OS나 루팅 부재를 판단할 수 없습니다."), null));
        audit.checks.add(new Check("부트·루팅·Knox·하드웨어 무결성", AuditRules.Status.UNKNOWN,
                "Verified Boot, 부트로더 잠금, Knox 보증 비트, 루트킷·변조 부품을 이 앱은 검증하지 못합니다. 키 증명·Play Integrity도 구현되어 있지 않습니다. 부팅 시 경고, 제조사 공식 업데이트 및 서비스센터 점검을 함께 확인하세요. 부트로더 잠금 변경·펌웨어 재설치는 실행하지 않습니다.", "update"));
        audit.checks.add(new Check("개발자 옵션 / USB·무선 디버깅", AuditRules.Status.MANUAL,
                "일반 앱에는 설정값이 제한되거나 0으로 표시될 수 있어 자동 안전 판정을 하지 않습니다. 개발자 옵션에서 USB·무선 디버깅을 직접 확인하고 불필요하면 끄세요. 항목이 없으면 사용 중이 아닐 수 있습니다.", "developer"));
        audit.accessibility(context);
        audit.administrators(context);
        audit.checks.add(new Check("특별 접근 권한 / VPN / 인증서", AuditRules.Status.MANUAL,
                "다른 앱 위에 표시, 알 수 없는 앱 설치, 알림 접근, VPN, 사용자 인증서는 설정에서 확인하세요. 전체 보유 앱이나 허용 상태를 전수 판독하지 못합니다. 업무용 VPN·인증서와 접근성 도구는 정상 용도일 수 있으므로 모르는 항목부터 확인하세요.", "security"));
        audit.checks.add(new Check("악성코드 검사 범위", AuditRules.Status.UNKNOWN,
                "앱의 권한·설치 출처·디버그 설정을 검토합니다. 백신 엔진·악성코드 DB·실시간 보호는 없습니다. 숨은 앱, 다른 사용자·업무 프로필, 앱 개인 데이터·메모리·펌웨어는 검사하지 못합니다. 신호가 없어도 감염 없음 판정이 아닙니다. Play 스토어의 Play 프로텍트에서도 직접 검사하세요.", "apps"));
        audit.applications(context);
        return audit;
    }
    private void unavailable(String title, String action) {
        checks.add(new Check(title, AuditRules.Status.UNKNOWN, "시스템이 조회를 허용하지 않거나 값을 제공하지 않았습니다. 설정에서 직접 확인하세요.", action));
    }
    private void accessibility(Context context) {
        try {
            AccessibilityManager manager = context.getSystemService(AccessibilityManager.class);
            if (manager == null) throw new IllegalStateException();
            List<AccessibilityServiceInfo> services = manager.getEnabledAccessibilityServiceList(AccessibilityServiceInfo.FEEDBACK_ALL_MASK);
            StringBuilder detail = new StringBuilder("API가 반환한 활성 서비스 " + services.size() + "개");
            for (AccessibilityServiceInfo service : services) detail.append("\n• ").append(service.getId());
            detail.append("\n정상 보조 도구도 포함됩니다. 모르는 서비스만 검토하고 필요한 보조 기능은 유지하세요. 기기 정책에 따라 목록이 제한될 수 있습니다.");
            checks.add(new Check("접근성 서비스", AuditRules.Status.OBSERVED, detail.toString(), "accessibility"));
        } catch (RuntimeException error) { unavailable("접근성 서비스", "accessibility"); }
    }
    private void administrators(Context context) {
        try {
            DevicePolicyManager manager = context.getSystemService(DevicePolicyManager.class);
            if (manager == null) throw new IllegalStateException();
            List<ComponentName> admins = manager.getActiveAdmins();
            if (admins == null) admins = Collections.emptyList();
            StringBuilder detail = new StringBuilder("API가 반환한 활성 관리자 " + admins.size() + "개");
            for (ComponentName admin : admins) detail.append("\n• ").append(admin.flattenToShortString());
            detail.append("\n업무용 관리 앱도 포함될 수 있습니다. 현재 사용자와 조회 범위에 한정됩니다. 모르는 관리 앱은 설정에서 권한과 설치 경위를 확인하세요.");
            checks.add(new Check("기기 관리자", AuditRules.Status.OBSERVED, detail.toString(), "admin"));
        } catch (RuntimeException error) { unavailable("기기 관리자", "admin"); }
    }
    private void applications(Context context) {
        PackageManager pm = context.getPackageManager();
        Set<String> packages = new HashSet<>();
        try {
            Intent launcher = new Intent(Intent.ACTION_MAIN).addCategory(Intent.CATEGORY_LAUNCHER);
            for (ResolveInfo info : pm.queryIntentActivities(launcher, 0)) if (info.activityInfo != null) packages.add(info.activityInfo.packageName);
            for (ApplicationInfo info : pm.getInstalledApplications(0)) packages.add(info.packageName);
            appsComplete = true;
        } catch (RuntimeException error) { appsComplete = false; }
        packages.remove(context.getPackageName());
        Set<String> sensitive = new HashSet<>(Arrays.asList("android.permission.READ_SMS", "android.permission.RECEIVE_SMS",
                "android.permission.SEND_SMS", "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
                "android.permission.READ_CONTACTS", "android.permission.READ_CALL_LOG", "android.permission.ACCESS_FINE_LOCATION",
                "android.permission.ACCESS_COARSE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION",
                "android.permission.READ_EXTERNAL_STORAGE", "android.permission.READ_MEDIA_IMAGES", "android.permission.READ_MEDIA_VIDEO"));
        for (String pkg : packages) {
            try {
                PackageInfo info = pm.getPackageInfo(pkg, PackageManager.GET_PERMISSIONS);
                ApplicationInfo application = info.applicationInfo;
                if (application == null) { appReadFailures++; continue; }
                App app = new App(); app.pkg = pkg; app.name = application.loadLabel(pm).toString();
                app.system = (application.flags & (ApplicationInfo.FLAG_SYSTEM | ApplicationInfo.FLAG_UPDATED_SYSTEM_APP)) != 0;
                if ((application.flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0) app.notes.add("디버그 가능 빌드: 개발 앱일 수 있음");
                if (application.targetSdkVersion < 28) app.notes.add("오래된 대상 SDK " + application.targetSdkVersion + ": 개발사 업데이트 확인");
                try {
                    app.source = Build.VERSION.SDK_INT >= 30 ? pm.getInstallSourceInfo(pkg).getInstallingPackageName() : pm.getInstallerPackageName(pkg);
                } catch (PackageManager.NameNotFoundException | RuntimeException error) { app.source = null; }
                if (app.source == null && !app.system) app.notes.add("설치 관리 앱 정보 없음: 복원·수동 설치 등일 수 있음");
                if (info.requestedPermissions != null) {
                    for (int i = 0; i < info.requestedPermissions.length; i++) {
                        String permission = info.requestedPermissions[i];
                        if (sensitive.contains(permission) && info.requestedPermissionsFlags != null
                                && i < info.requestedPermissionsFlags.length && AuditRules.granted(info.requestedPermissionsFlags[i])) {
                            app.grants.add(permission.substring("android.permission.".length()));
                        }
                        if ("android.permission.REQUEST_INSTALL_PACKAGES".equals(permission)) app.notes.add("패키지 설치 요청 권한 선언 (허용 상태는 수동 확인)");
                        if ("android.permission.SYSTEM_ALERT_WINDOW".equals(permission)) app.notes.add("다른 앱 위에 표시 권한 선언 (허용 상태는 수동 확인)");
                    }
                }
                apps.add(app);
            } catch (PackageManager.NameNotFoundException | RuntimeException error) { appReadFailures++; }
        }
        apps.sort(Comparator.<App>comparingInt(app -> app.notes.size()).reversed().thenComparing(app -> app.name));
    }
    public String summary() {
        StringBuilder out = new StringBuilder("RefurbCheck 0.2.0 독립 구현\n시각: " + timestamp
                + "\n안전·감염 없음·하드웨어 무결성을 보증하지 않습니다.\n");
        for (Check check : checks) out.append("\n[").append(AuditRules.label(check.result.status)).append("] ").append(check.title).append("\n").append(check.result.detail).append("\n");
        out.append("\n접근 가능한 앱 ").append(apps.size()).append("개 · 조회 실패 ").append(appReadFailures)
                .append("개 · 전수 검사 아님 · 목록 조회 ").append(appsComplete ? "완료" : "불완전").append("\n");
        for (App app : apps) {
            if (out.length() > 100000) {
                out.append("\n공유 크기 제한으로 이후 앱 목록은 생략했습니다. 앱 화면에서 나머지를 확인하세요.\n");
                break;
            }
            out.append("\n").append(app.name).append(" (").append(app.pkg).append(")\n설치 관리자: ")
                    .append(app.source == null ? "확인 불가" : app.source).append("\n참고 신호: ").append(app.notes)
                    .append("\n민감 권한 허용: ").append(app.grants).append("\n");
        }
        return out.toString();
    }
}
