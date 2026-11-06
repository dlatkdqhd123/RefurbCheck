package io.github.dlatkdqhd123.refurbcheck.prototype;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.graphics.Color;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;
import android.view.View;
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import android.widget.Toast;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends Activity {
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private LinearLayout body;
    private DeviceAudit report;
    private int shownApps;
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        body = new LinearLayout(this); body.setOrientation(LinearLayout.VERTICAL);
        body.setPadding(dp(20), dp(24), dp(20), dp(32));
        scroll.addView(body); setContentView(scroll);
        scroll.setOnApplyWindowInsetsListener((view, insets) -> {
            view.setPadding(insets.getSystemWindowInsetLeft(), insets.getSystemWindowInsetTop(),
                    insets.getSystemWindowInsetRight(), insets.getSystemWindowInsetBottom());
            return insets;
        });
        heading("RefurbCheck", 28);
        text("갤럭시 리퍼폰 보안 점검 · 무료 · 오프라인\n새 독립 구현 0.2.0 · 기존 1.1.0 업데이트 아님");
        text("공개 API로 볼 수 있는 상태와 앱 위험 신호만 확인합니다. 악성코드·하드웨어 해킹 부재를 증명하거나 OS 무결성을 확정하지 못합니다. 결과는 이 앱을 닫으면 보관되지 않습니다.");
        button("점검 시작", view -> scan());
    }
    private void scan() {
        body.removeAllViews(); heading("점검 중…", 24);
        text("기기의 공개 상태와 접근 가능한 앱을 읽고 있습니다. 외부 전송이나 자동 설정 변경은 없습니다.");
        worker.execute(() -> {
            try {
                DeviceAudit result = DeviceAudit.run(getApplicationContext());
                runOnUiThread(() -> { if (!isFinishing() && !isDestroyed()) { report = result; render(); } });
            } catch (RuntimeException error) {
                runOnUiThread(() -> { if (!isFinishing() && !isDestroyed()) {
                    body.removeAllViews(); heading("점검을 완료하지 못했습니다", 24);
                    text("접근 제한 또는 시스템 오류가 발생했습니다. 안전 판정을 하지 않습니다.");
                    button("다시 시도", view -> scan());
                }});
            }
        });
    }
    private void render() {
        body.removeAllViews(); shownApps = 0;
        heading("점검 결과", 28);
        text("0.2.0 · " + report.timestamp + "\n감염 없음 / 정상 기기 판정이 아닙니다. 설정을 변경하거나 돌아온 후 다시 점검하세요.");
        button("다시 점검", view -> scan());
        button("보고서 공유…", view -> new AlertDialog.Builder(this).setTitle("보고서 공유")
                .setMessage("기기 모델, OS, 활성 서비스와 앱 목록·권한·설치 출처가 포함됩니다. 선택한 외부 앱으로 전달됩니다. 계속할까요?")
                .setNegativeButton("취소", null).setPositiveButton("공유 앱 선택", (dialog, which) ->
                        open(new Intent(Intent.ACTION_SEND).setType("text/plain").putExtra(Intent.EXTRA_TEXT, report.summary()), true)).show());
        for (DeviceAudit.Check check : report.checks) {
            heading("[" + AuditRules.label(check.result.status) + "] " + check.title, 19);
            text(check.result.detail);
            if (check.action != null) button("관련 설정 열기", view -> settings(check.action));
        }
        heading("직접 확인할 설정", 22);
        button("다른 앱 위에 표시", view -> open(new Intent(Settings.ACTION_MANAGE_OVERLAY_PERMISSION), false));
        button("알 수 없는 앱 설치", view -> open(new Intent(Settings.ACTION_MANAGE_UNKNOWN_APP_SOURCES), false));
        button("알림 접근", view -> open(new Intent(Settings.ACTION_NOTIFICATION_LISTENER_SETTINGS), false));
        button("VPN 설정", view -> open(new Intent(Settings.ACTION_VPN_SETTINGS), false));
        button("보안·인증서 / Play 프로텍트 안내", view -> new AlertDialog.Builder(this).setTitle("추가 점검")
                .setMessage("삼성 설정 > 보안 및 개인정보 보호에서 업데이트·기타 보안 설정·사용자 인증서를 확인하세요. 경로는 기기마다 다릅니다. Play 스토어 > 프로필 > Play 프로텍트 > 검사도 직접 실행하세요. 의심되는 앱은 먼저 설치 경위를 확인하세요. 부트로더 조작·초기화는 데이터 손실이 있으므로 여기서 실행하지 않습니다.")
                .setPositiveButton("확인", null).show());
        heading("접근 가능한 앱 " + report.apps.size() + "개", 22);
        text("전체 앱·다른 사용자·숨겨진 서비스의 전수 목록이 아닙니다. 조회 실패 " + report.appReadFailures
                + "개. 목록 조회 " + (report.appsComplete ? "완료" : "불완전")
                + ". 참고 신호가 많은 앱부터 표시합니다. 권한·출처·개발 빌드는 감염 증거가 아닙니다. 시스템 앱도 표시하되 삭제는 제공하지 않습니다. RefurbCheck 자체는 목록에서 제외합니다.");
        appendApps();
    }
    private void appendApps() {
        int end = Math.min(shownApps + 30, report.apps.size());
        for (; shownApps < end; shownApps++) {
            DeviceAudit.App app = report.apps.get(shownApps);
            heading(app.name + (app.system ? " · 시스템" : ""), 18);
            text(app.pkg + "\n설치 관리자: " + (app.source == null ? "확인 불가" : app.source)
                    + "\n참고 신호: " + (app.notes.isEmpty() ? "해당 규칙 신호 없음 (안전 판정 아님)" : String.join(" / ", app.notes))
                    + "\n허용된 민감 권한: " + (app.grants.isEmpty() ? "목록에서 확인되지 않음 (모든 권한을 다루지 않음)" : String.join(", ", app.grants)));
            button("앱 정보·권한 확인", view -> open(new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + app.pkg)), false));
            if (!app.system) button("삭제 방법…", view -> new AlertDialog.Builder(this).setTitle(app.name + " 삭제 검토")
                    .setMessage("이 신호만으로 악성 앱이라고 판단하지 마세요. 삭제하면 해당 앱의 데이터가 손실될 수 있습니다. 앱 정보 화면에서 직접 삭제를 선택하고 Android 확인 창에서 최종 결정하세요. 관리자 앱은 먼저 권한 검토가 필요할 수 있습니다.")
                    .setNegativeButton("취소", null).setPositiveButton("앱 정보 열기", (dialog, which) ->
                            open(new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS, Uri.parse("package:" + app.pkg)), false)).show());
        }
        if (shownApps < report.apps.size()) {
            Button more = button("앱 더 보기 (" + shownApps + "/" + report.apps.size() + ")", null);
            more.setOnClickListener(view -> { body.removeView(more); appendApps(); });
        }
    }
    private void settings(String key) {
        String action;
        switch (key) {
            case "update": action = Settings.ACTION_SETTINGS; break;
            case "developer": action = Settings.ACTION_APPLICATION_DEVELOPMENT_SETTINGS; break;
            case "accessibility": action = Settings.ACTION_ACCESSIBILITY_SETTINGS; break;
            case "admin": action = "android.settings.DEVICE_ADMIN_SETTINGS"; break;
            case "apps": action = Settings.ACTION_MANAGE_APPLICATIONS_SETTINGS; break;
            default: action = Settings.ACTION_SECURITY_SETTINGS;
        }
        open(new Intent(action), false);
    }
    private void open(Intent intent, boolean chooser) {
        try { startActivity(chooser ? Intent.createChooser(intent, "보고서를 공유할 앱") : intent); }
        catch (ActivityNotFoundException | SecurityException error) {
            Toast.makeText(this, "이 기기에서 화면을 열 수 없습니다. 설정 앱에서 직접 확인하세요.", Toast.LENGTH_LONG).show();
        }
    }
    private int dp(int value) { return Math.round(value * getResources().getDisplayMetrics().density); }
    private void heading(String value, int size) {
        TextView view = new TextView(this); view.setText(value); view.setTextSize(size);
        view.setTextColor(Color.rgb(20, 45, 65)); view.setPadding(0, dp(18), 0, dp(6)); body.addView(view);
    }
    private void text(String value) {
        TextView view = new TextView(this); view.setText(value); view.setTextSize(16);
        view.setTextColor(Color.rgb(40, 40, 40)); view.setTextIsSelectable(true);
        view.setPadding(0, dp(4), 0, dp(10)); body.addView(view);
    }
    private Button button(String value, View.OnClickListener listener) {
        Button view = new Button(this); view.setText(value); view.setAllCaps(false);
        view.setOnClickListener(listener); body.addView(view); return view;
    }
    @Override public void onDestroy() { worker.shutdownNow(); report = null; super.onDestroy(); }
}
