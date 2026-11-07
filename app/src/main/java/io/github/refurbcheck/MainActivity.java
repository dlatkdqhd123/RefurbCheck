package io.github.refurbcheck;

import android.app.Activity;
import android.app.AlertDialog;
import android.content.Intent;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.provider.Settings;
import android.text.Editable;
import android.text.TextWatcher;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.WindowManager;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.Switch;
import android.widget.TextView;
import android.widget.Toast;
import org.json.JSONArray;
import org.json.JSONObject;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.HashSet;
import java.util.Set;

public final class MainActivity extends Activity implements ScanSession.Listener {
    private static final int INK=0xff172c3c, MUTED=0xff526473, BG=0xfff3f6f8, TEAL=0xff166b63;
    private static final int EXPORT=100, REFERENCE=101, CATALOG=102;
    private final ScanSession session=ScanSession.INSTANCE;
    private LinearLayout root,content,appList;
    private TextView liveStage;
    private int selectedTab=0,filter=0,appPage=0;
    private boolean allApps=false,wasRunning=false,resumed=false,automaticPromptPosted=false;
    private boolean detailsExpanded=false;
    private String query="",lastRenderedPhase="";

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        if(saved!=null) {selectedTab=saved.getInt("tab");detailsExpanded=saved.getBoolean("detailsExpanded");}
        session.automaticRemovalPrompts=getPreferences(MODE_PRIVATE).getBoolean("postResetRemovalMode",true);
        session.automaticCatalogUpdates=getPreferences(MODE_PRIVATE).getBoolean("automaticCatalogUpdates",true);
        session.listener=this;
        render();
        if(saved==null||session.flowSnapshot().optString("runId").isEmpty()) session.startOneRun(this);
    }
    @Override protected void onSaveInstanceState(Bundle state) {
        super.onSaveInstanceState(state); state.putInt("tab",selectedTab);state.putBoolean("detailsExpanded",detailsExpanded);
    }
    @Override protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);setIntent(intent);
        if(Intent.ACTION_MAIN.equals(intent.getAction())&&intent.hasCategory(Intent.CATEGORY_LAUNCHER)) startFresh();
    }
    @Override protected void onResume() {
        super.onResume();resumed=true;session.listener=this;
        if(session.pendingRemediation!=null&&session.leftForRemediation) session.returnedFromRemediation(this);
        changed();
    }
    @Override protected void onPause() {
        resumed=false;
        getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        if(session.pendingRemediation!=null) session.leftForRemediation=true;
        super.onPause();
    }
    @Override protected void onDestroy() { if(session.listener==this) session.listener=null; super.onDestroy(); }
    @Override public void changed() {
        if(isFinishing()||isDestroyed()) return;
        String phase=session.flowSnapshot().optString("phase");
        if(resumed&&(session.running||session.remediationBusy)) getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        else getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        if(wasRunning&&session.running&&liveStage!=null&&phase.equals(lastRenderedPhase)) { liveStage.setText(session.stage); return; }
        render();
    }

    private void startFresh() {selectedTab=0;detailsExpanded=false;session.startOneRun(this);render();}

    private void render() {
        wasRunning=session.running;
        lastRenderedPhase=session.flowSnapshot().optString("phase");
        if(resumed&&(session.running||session.remediationBusy)) getWindow().addFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        else getWindow().clearFlags(WindowManager.LayoutParams.FLAG_KEEP_SCREEN_ON);
        liveStage=null;
        root=column(); root.setBackgroundColor(BG);
        root.setPadding(dp(18),dp(16),dp(18),dp(8));
        if(android.os.Build.VERSION.SDK_INT>=35) root.setOnApplyWindowInsetsListener((v,insets)->{
            android.graphics.Insets bars=insets.getInsets(android.view.WindowInsets.Type.systemBars());
            v.setPadding(dp(18)+bars.left,dp(16)+bars.top,dp(18)+bars.right,dp(8)+bars.bottom); return insets;
        });
        setContentView(root);
        TextView eyebrow=text("REFURBCHECK  ·  1.4.0",11,TEAL); eyebrow.setLetterSpacing(.13f); root.addView(eyebrow);
        TextView title=text("한 번에 점검",27,INK); title.setTypeface(null,Typeface.BOLD); root.addView(title);
        TextView subtitle=text("갤럭시 · 실행부터 조치 결과까지",13,MUTED); margin(subtitle,0,4,0,12); root.addView(subtitle);
        ScrollView sc=new ScrollView(this); sc.setFillViewport(false);
        content=column(); content.setPadding(0,0,0,dp(12)); sc.addView(content);
        root.addView(sc,new LinearLayout.LayoutParams(-1,0,1));
        if(selectedTab==0) results(); else if(selectedTab==1) apps(); else if(selectedTab==2) remediation(); else guide();
        LinearLayout nav=row(); String[] tabs={"한번에","앱","조치","안내·비교"};
        for(int i=0;i<tabs.length;i++) {
            final int n=i; Button b=button(tabs[i],()->{selectedTab=n;render();},i==selectedTab);
            LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(0,dp(52),1); p.setMargins(dp(2),dp(4),dp(2),0); nav.addView(b,p);
        }
        root.addView(nav);
        maybeStartAutomaticRemoval();
    }

    private void maybeStartAutomaticRemoval() {
        if(!resumed||automaticPromptPosted||session.running||session.remediationBusy||session.catalogBusy||session.pendingRemediation!=null
                ||isFinishing()||isDestroyed()) return;
        JSONObject next=session.nextAutomaticRemoval(getPackageName());if(next==null) return;
        automaticPromptPosted=true;
        session.main.post(()->{
            automaticPromptPosted=false;
            if(!resumed||session.running||session.remediationBusy||session.catalogBusy||session.pendingRemediation!=null||isFinishing()||isDestroyed()) return;
            JSONObject current=session.nextAutomaticRemoval(getPackageName());if(current==null) return;
            String pkg=current.optString("packageName");session.attemptedRemoval(pkg);
            RemediationAction action=new RemediationAction(RemediationAction.Kind.UNINSTALL,pkg,
                    "malware.app."+pkg,"WARN");
            session.logRemediation(action.id(),"AUTO_REMOVAL_PREFLIGHT","초기화 직후 모드: 공개 파일 자료와 일치한 일반 앱을 재검증합니다. Android에서 삭제를 승인해야 제거됩니다.");
            beginRemediation(action,true);
        });
    }

    private void postResetModeControl() {
        LinearLayout box=card();
        Switch mode=new Switch(this);mode.setText("초기화 직후 정책 · 검출 앱 삭제 확인 자동 진행");
        mode.setTextSize(14);mode.setTextColor(INK);mode.setChecked(session.automaticRemovalPrompts);box.addView(mode);
        box.addView(text("직접 설치한 감시·관리 앱이 없는 기기를 위한 모드입니다. 정확한 파일 지표가 일치한 일반 앱만 삭제 직전에 다시 확인하고 Android 승인창을 엽니다. 취소하면 자동 진행을 멈춥니다.",12,MUTED));
        mode.setOnCheckedChangeListener((button,checked)->{
            session.automaticRemovalPrompts=checked;
            getPreferences(MODE_PRIVATE).edit().putBoolean("postResetRemovalMode",checked).apply();
            if(!checked) session.pauseAutomaticRemoval("자동 삭제 안내를 껐습니다. 확인한 결과는 유지합니다.");
            else toast("다음 새 점검부터 자동 삭제 안내를 적용합니다.");
            render();
        });
        content.addView(box);
    }

    private void results() {
        JSONObject flow=session.flowSnapshot();String phase=flow.optString("phase","IDLE");
        boolean busy=session.running||session.remediationBusy||session.catalogBusy||session.pendingRemediation!=null;
        boolean stopped=flow.optBoolean("cancelled")||flow.optBoolean("paused");
        boolean complete="COMPLETE".equals(phase);
        LinearLayout hero=card();
        TextView heading=text(flowHeading(phase,busy),22,stopped?0xff865000:INK);heading.setTypeface(null,Typeface.BOLD);hero.addView(heading);
        liveStage=text(session.catalogBusy?session.catalogMessage:session.stage,14,MUTED);margin(liveStage,0,8,0,10);hero.addView(liveStage);
        String[] steps={"자료 확인","전체 검사","검출 앱 조치","재확인","결과 정리"};
        int stage=session.catalogBusy?1:Math.max(1,Math.min(5,flow.optInt("stageNumber",1)));
        for(int i=0;i<steps.length;i++) {
            boolean active=i+1==stage;String note="";
            if(i==0) note=networkLabel(flow.optString("networkUpdateState"));
            else if(i==2&&flow.optBoolean("initialScanComplete")) note="삭제 대상 "+flow.optInt("eligibleCount")+"개 · 제거 확인 "+flow.optInt("removedCount")+"개";
            else if(i==3&&flow.optBoolean("recheckPerformed")) note="조치 후 전체 재검사 수행";
            else if(i==3&&complete) note="자동 제거 없음 · 최초 검사 결과 유지";
            else if(i==4&&complete) note="검사 범위와 남은 확인 사항 정리";
            TextView step=text((active?"● ":"○ ")+(i+1)+"  "+steps[i]+(note.isEmpty()?"":"  ·  "+note),13,active?TEAL:MUTED);
            if(active) step.setTypeface(null,Typeface.BOLD);margin(step,0,2,0,2);hero.addView(step);
        }
        if(busy) {
            ProgressBar p=new ProgressBar(this,null,android.R.attr.progressBarStyleHorizontal);p.setIndeterminate(true);margin(p,0,12,0,8);hero.addView(p,new LinearLayout.LayoutParams(-1,dp(7)));
            hero.addView(text(session.pendingRemediation!=null?"Android 화면에서 필요한 승인을 마친 뒤 돌아오면 확인을 이어갑니다.":"별도 시작 버튼 없이 진행합니다. 화면을 회전해도 같은 점검이 이어집니다.",12,MUTED));
            Button stop=button("자동 점검 중단",session::cancel,false);stop.setContentDescription("자동 점검 중단");stop.setEnabled(!(session.catalogBusy?flow.optBoolean("catalogUpdateCancellationRequested"):flow.optBoolean("cancellationRequested")));hero.addView(stop);
        } else if(!flow.optBoolean("initialScanComplete")&&!stopped) {
            hero.addView(button("한 번에 점검 시작",this::startFresh,true));
        } else {
            hero.addView(text("제거 확인 "+flow.optInt("removedCount")+"개  ·  조치 보류 "+flow.optInt("blockedCount")+"개",14,INK));
            if(flow.optInt("removedCount")>0) hero.addView(text("현재 프로필에서 다시 찾지 못한 앱 수입니다. 다른 프로필까지 제거했다는 뜻은 아닙니다.",12,MUTED));
            String detail=flow.optString("statusDetail");if(!detail.isEmpty()) hero.addView(text(detail,12,MUTED));
            if(stopped) hero.addView(text("자동 진행이 멈췄습니다. 아직 처리하지 않은 항목을 해결 완료로 표시하지 않습니다.",13,0xff865000));
            hero.addView(button(stopped?"새 점검으로 다시 시작":"처음부터 다시 점검",this::startFresh,false));
        }
        content.addView(hero);
        if(session.report!=null&&!session.running) {
            ScanReport r=session.report;LinearLayout summary=card();
            TextView verdict=text(r.verdict(),20,statusColor(r.count(Finding.Status.ALERT)>0?Finding.Status.ALERT:r.count(Finding.Status.WARN)>0?Finding.Status.WARN:Finding.Status.INFO));verdict.setTypeface(null,Typeface.BOLD);summary.addView(verdict);
            summary.addView(text("중요 징후 "+r.count(Finding.Status.ALERT)+"  ·  확인 필요 "+r.count(Finding.Status.WARN)+"  ·  확인 불가 "+r.count(Finding.Status.UNKNOWN),13,INK));
            JSONObject apk=r.evidence.optJSONObject("apkCoverage");if(apk!=null) summary.addView(text("APK 해시 "+apk.optInt("filesHashed")+" / "+apk.optInt("filesDiscovered")+"개 · "+(apk.optBoolean("complete")?"읽기 범위 완료":"미확인 범위 있음"),12,MUTED));
            summary.addView(text("자동 흐름의 완료는 기기 전체의 안전 판정이 아닙니다.",12,MUTED));content.addView(summary);
            if(!busy) nextManualAction();
            content.addView(button(detailsExpanded?"상세 검사 결과 접기":"상세 검사 결과와 근거 보기",()->{detailsExpanded=!detailsExpanded;render();},false));
            if(detailsExpanded) detailedResults();
            if(!busy) content.addView(button("결과 JSON 저장",this::exportReport,false));
        }
        if(!busy) {
            LinearLayout more=row();weighted(more,button("모든 조치 보기",()->{selectedTab=2;render();},false));weighted(more,button("진행 옵션·안내",()->{selectedTab=3;render();},false));content.addView(more);
        }
        limitation();
    }

    private String flowHeading(String phase,boolean busy) {
        JSONObject flow=session.flowSnapshot();
        if(session.catalogBusy) return flow.optBoolean("catalogUpdateCancellationRequested")?"자료 확인 중단 처리 중":"검사 자료 확인 중";
        if(flow.optBoolean("cancellationRequested")&&busy) return "중단 요청 처리 중";
        switch(phase) {
            case "UPDATING":return "검사 자료 확인 중";
            case "SCANNING":return "자동 점검 중";
            case "PREPARING_REMOVAL":return "삭제 전 근거 재확인";
            case "AWAITING_APPROVAL":return "Android 삭제 승인 대기";
            case "VERIFYING_REMOVAL":return "제거 여부 확인 중";
            case "RECHECKING":return "조치 후 다시 점검 중";
            case "COMPLETE":return "자동 흐름 완료";
            case "PAUSED":return "자동 조치 일시 중지";
            case "CANCELLED":return "자동 점검 중단됨";
            default:return "자동 점검 준비";
        }
    }

    private String networkLabel(String state) {
        if(state.isEmpty()||"NOT_CHECKED".equals(state)) return "확인 준비";
        if(state.contains("DISABLED")) return "자동 갱신 꺼짐";
        if(state.contains("NO_WIFI")) return "Wi-Fi 미연결 · 보유 자료 사용";
        if(state.contains("THROTTLED")) return "확인 간격 내 · 보유 자료 사용";
        if(state.contains("FAILED")) return "갱신 확인 실패 · 보유 자료 사용";
        if(state.contains("CANCEL")) return "갱신 확인 중단";
        if(state.contains("PENDING")||state.contains("CHECKING")) return "서명된 자료 확인 중";
        if(state.contains("INSTALL")||state.contains("CURRENT")||state.contains("NO_CHANGE")) return "서명 자료 확인 처리됨";
        return "확인 내역 기록됨";
    }

    private void nextManualAction() {
        if(session.report==null) return;
        List<Finding> sorted=new ArrayList<>(session.report.findings);Collections.sort(sorted,(a,b)->Integer.compare(rank(a.status),rank(b.status)));
        Set<String> opened=new HashSet<>();JSONArray log=session.logSnapshot();
        for(int i=0;i<log.length();i++) {JSONObject entry=log.optJSONObject(i);if(entry!=null&&"SCREEN_OPENED".equals(entry.optString("outcome"))) opened.add(entry.optString("action"));}
        RemediationAction chosen=null;Finding source=null;Set<String> seen=new HashSet<>();
        for(Finding f:sorted) {
            if(f.status!=Finding.Status.ALERT&&f.status!=Finding.Status.WARN) continue;
            RemediationAction a=RemediationAction.forFinding(f);if(a==null||!seen.add(a.id())) continue;
            if(chosen==null) {chosen=a;source=f;}
            if(!opened.contains(a.id())) {chosen=a;source=f;break;}
        }
        if(chosen==null) return;
        final RemediationAction action=chosen;LinearLayout box=card();TextView h=text("직접 확인할 다음 항목",17,INK);h.setTypeface(null,Typeface.BOLD);box.addView(h);
        box.addView(text(source.title,15,INK));box.addView(text(session.cancelled.get()?"이 항목은 Android 또는 삼성 화면에서 확인해야 합니다. 중단된 흐름은 자동 재검사를 하지 않으므로 확인 후 새 점검을 시작하세요.":"이 항목은 Android 또는 삼성 화면에서 확인해야 합니다. 돌아오면 관측 가능한 범위를 다시 검사합니다.",12,MUTED));
        box.addView(button(action.label(),()->beginRemediation(action),true));content.addView(box);
    }

    private void detailedResults() {
        ScanReport r=session.report;if(r==null) return;
        LinearLayout box=card();box.addView(text("이번 검사 상세",18,INK));
        box.addView(text("검사 "+r.findings.size()+"항목  ·  "+new SimpleDateFormat("MM.dd HH:mm",Locale.KOREA).format(new Date(r.completedAt)),12,MUTED));
        JSONObject malware=r.evidence.optJSONObject("malwareCoverage");
        if(malware!=null) {
            box.addView(text("악성·감시 자료 대조 · APK "+malware.optInt("wholeFilesCompared")+"개 / 내부 파일 "+malware.optLong("entriesHashed")+"개 · 일치 "+malware.optInt("matchingPackages")+"개 앱",13,INK));
            box.addView(text(malware.optBoolean("complete")?"직접 파일 검사 범위 완료 · 알려지지 않은 악성코드는 놓칠 수 있습니다.":"악성 파일 검사에 미확인 범위가 있습니다. 상세 근거를 확인하세요.",12,MUTED));
        }
        content.addView(box);
        LinearLayout filters=row();
        String[] fs={"전체","확인 필요","확인 불가"};
        for(int i=0;i<fs.length;i++) { final int f=i; weighted(filters,button(fs[i],()->{filter=f;render();},filter==i)); }
        margin(filters,0,10,0,6); content.addView(filters);
        List<Finding> items=new ArrayList<>(r.findings); Collections.sort(items,(a,b)->Integer.compare(rank(a.status),rank(b.status)));
        int shown=0;
        for(Finding f:items) {
            if(filter==1&&f.status!=Finding.Status.ALERT&&f.status!=Finding.Status.WARN) continue;
            if(filter==2&&f.status!=Finding.Status.UNKNOWN) continue;
            finding(f); shown++;
        }
        if(shown==0) content.addView(text("이 분류에 해당하는 항목이 없습니다.",14,MUTED));
    }

    private void catalogControls() {
        LinearLayout box=card();
        TextView title=text("검사 자료 업데이트",17,INK);title.setTypeface(null,Typeface.BOLD);box.addView(title);
        Switch automatic=new Switch(this);automatic.setText("Wi-Fi에서 검사 자료 자동 확인");
        automatic.setTextSize(14);automatic.setTextColor(INK);automatic.setChecked(session.automaticCatalogUpdates);
        automatic.setOnCheckedChangeListener((button,checked)->{
            session.automaticCatalogUpdates=checked;session.catalogUpdatePreferenceChanged();
            getPreferences(MODE_PRIVATE).edit().putBoolean("automaticCatalogUpdates",checked).apply();
        });box.addView(automatic);
        box.addView(text("새 점검을 시작할 때 Wi-Fi에서 GitHub 검사 자료를 확인하며, 자동 확인은 6시간 이내에 반복하지 않습니다. 앱 목록·APK·검사 보고서는 전송하지 않습니다. 서명과 유효기간을 확인한 자료만 적용하며, 적용 후 다시 검사합니다.",12,MUTED));
        if(session.report!=null) {
            JSONObject database=session.report.evidence.optJSONObject("malwareDatabase");
            if(database!=null) {
                box.addView(text("사용 자료: "+database.optInt("entryCount")+"개 · 구성일 "+database.optString("snapshotDate","미확인"),12,MUTED));
                JSONObject update=database.optJSONObject("update");
                if(update!=null) box.addView(text((update.optBoolean("signedUpdate")?"서명된 업데이트 #"+update.optLong("sequence"):"APK에 포함된 기본 자료")
                        +(database.optBoolean("automaticRemovalAllowed")?" · 유효기간 내":" · 자동 삭제 연결 보류"),12,MUTED));
            }
        }
        if(!session.catalogMessage.isEmpty()) box.addView(text(session.catalogMessage,13,MUTED));
        boolean enabled=!session.running&&!session.remediationBusy&&!session.catalogBusy&&session.pendingRemediation==null;
        Button download=button("지금 업데이트 확인",()->session.updateCatalog(this,null),true);download.setEnabled(enabled);box.addView(download);
        Button fromFile=button("서명된 자료 파일 가져오기",this::chooseCatalog,false);fromFile.setEnabled(enabled);box.addView(fromFile);
        box.addView(text("수동 확인은 현재 인터넷 연결을 사용합니다. 새 자료를 배포하지 않은 기간과 알려지지 않은 악성코드는 검사에 한계가 있습니다.",12,MUTED));
        content.addView(box);
    }

    private void chooseCatalog() {
        if(session.running||session.remediationBusy||session.catalogBusy) {toast("현재 작업을 마친 뒤 시도하세요.");return;}
        Intent intent=new Intent(Intent.ACTION_OPEN_DOCUMENT);intent.addCategory(Intent.CATEGORY_OPENABLE);intent.setType("*/*");
        intent.putExtra(Intent.EXTRA_MIME_TYPES,new String[]{"application/zip","application/octet-stream","application/x-zip-compressed"});
        try {startActivityForResult(intent,CATALOG);}catch(Exception error){toast("파일 선택 화면을 열 수 없습니다.");}
    }

    private void limitation() {
        LinearLayout box=column(); box.setPadding(dp(14),dp(12),dp(14),dp(12)); box.setBackground(bg(0xffe7eef2,12));
        TextView t=text("공장 출고 상태·악성코드 없음·물리 부품 무변조를 보증하는 검사가 아닙니다.",14,INK); t.setTypeface(null,Typeface.BOLD); box.addView(t);
        box.addView(text("읽을 수 없거나 실시하지 않은 항목은 ‘확인 불가’로 남깁니다. 결과는 검사한 휴대전화 안에서 관측한 참고 정보입니다.",13,MUTED));
        margin(box,0,0,0,12); content.addView(box);
    }

    private void finding(Finding f) {
        LinearLayout box=card();
        TextView category=text(f.category+"  ·  "+statusLabel(f.status),12,statusColor(f.status)); box.addView(category);
        TextView title=text(f.title,17,INK); title.setTypeface(null,Typeface.BOLD); margin(title,0,5,0,4); box.addView(title);
        TextView preview=text("근거와 조치 보기  +",12,MUTED); box.addView(preview);
        LinearLayout details=column(); details.setVisibility(View.GONE);
        details.addView(text("증거 출처: "+f.evidenceLabel()+" · "+new SimpleDateFormat("HH:mm:ss",Locale.KOREA).format(new Date(f.observedAt)),12,MUTED));
        TextView evidence=text(f.detail,14,INK); evidence.setTextIsSelectable(true); margin(evidence,0,10,0,8); details.addView(evidence);
        if(f.action!=null&&!f.action.isEmpty()) { TextView action=text("확인 방법\n"+f.action,13,TEAL); action.setTextIsSelectable(true); details.addView(action); }
        RemediationAction action=RemediationAction.forFinding(f);
        if(action!=null) details.addView(button(action.label(),()->beginRemediation(action),false));
        if(f.id.startsWith("malware.app.")) {
            JSONObject pkg=RemediationController.findPackage(session.report,f.id.substring("malware.app.".length()));
            if(RemediationController.canRemove(pkg,getPackageName())) {
                RemediationAction remove=new RemediationAction(RemediationAction.Kind.UNINSTALL,pkg.optString("packageName"),f.id,f.status.name());
                details.addView(button(remove.label(),()->beginRemediation(remove),true));
            }
        }
        box.addView(details);
        box.setOnClickListener(v->{ boolean show=details.getVisibility()!=View.VISIBLE; details.setVisibility(show?View.VISIBLE:View.GONE); preview.setText(show?"접기  −":"근거와 조치 보기  +"); });
        box.setContentDescription(f.title+", "+statusLabel(f.status)+", 눌러서 근거 펼치기");
        content.addView(box);
    }

    private void apps() {
        ScanReport r=session.report;
        if(r==null) { content.addView(text(session.running?"점검이 끝나면 앱 목록을 볼 수 있습니다.":"먼저 종합 점검을 실행하세요.",16,INK)); return; }
        TextView h=text("설치 앱 "+r.inventory.length()+"개",22,INK); h.setTypeface(null,Typeface.BOLD); content.addView(h);
        content.addView(text("현재 사용자 프로필에서 보이는 앱입니다. 앱 이름·설치 출처·권한만으로 악성 여부를 판정하지 않습니다.",13,MUTED));
        EditText search=new EditText(this); search.setSingleLine(true); search.setTextSize(15); search.setTextColor(INK); search.setHint("앱 이름 또는 패키지 검색"); search.setText(query); margin(search,0,10,0,8); content.addView(search);
        content.addView(button(allApps?"전체 앱 표시 중 · 사용자 앱만 보기":"사용자 앱 표시 중 · 시스템 앱도 보기",()->{allApps=!allApps;appPage=0;render();},false));
        appList=column(); content.addView(appList); fillApps();
        search.addTextChangedListener(new TextWatcher() {
            public void beforeTextChanged(CharSequence s,int st,int c,int a) { }
            public void onTextChanged(CharSequence s,int st,int before,int count) { query=s.toString();appPage=0;fillApps(); }
            public void afterTextChanged(Editable e) { }
        });
    }

    private void fillApps() {
        if(appList==null||session.report==null) return;
        appList.removeAllViews(); JSONArray a=session.report.inventory; List<JSONObject> matches=new ArrayList<>();
        String q=query.toLowerCase(Locale.ROOT);
        for(int i=0;i<a.length();i++) {
            JSONObject p=a.optJSONObject(i); if(p==null||(!allApps&&p.optBoolean("system"))) continue;
            if((p.optString("label")+" "+p.optString("packageName")).toLowerCase(Locale.ROOT).contains(q)) matches.add(p);
        }
        Collections.sort(matches,(x,y)->x.optString("label").compareToIgnoreCase(y.optString("label")));
        appPage=Math.min(appPage,Math.max(0,(matches.size()-1)/30));
        int start=appPage*30,end=Math.min(start+30,matches.size());
        TextView count=text("표시 "+matches.size()+"개"+(matches.isEmpty()?"":" · "+(start+1)+"–"+end),12,MUTED); margin(count,0,10,0,8); appList.addView(count);
        for(int i=start;i<end;i++) {
            JSONObject p=matches.get(i); LinearLayout box=card();
            TextView label=text(p.optString("label",p.optString("packageName")),17,INK); label.setTypeface(null,Typeface.BOLD); box.addView(label);
            box.addView(text(p.optString("packageName"),12,MUTED));
            box.addView(text((p.optBoolean("system")?"시스템 앱":"사용자 앱")+" · "+p.optString("versionName","버전 미상"),12,MUTED));
            box.addView(text("출처: "+(p.optString("installer").isEmpty()?"확인 불가 / 기본 설치":p.optString("installer")),12,MUTED));
            JSONObject provenance=p.optJSONObject("installProvenance");
            if(provenance!=null) {
                String initiator=provenance.optString("initiatingPackageName","");
                String owner=provenance.optString("updateOwnerPackageName","");
                if(!initiator.isEmpty()&&!"null".equals(initiator)) box.addView(text("최초 설치 요청 앱: "+initiator,12,MUTED));
                if(!owner.isEmpty()&&!"null".equals(owner)) box.addView(text("업데이트 소유 앱: "+owner,12,MUTED));
            }
            JSONArray history=p.optJSONArray("signingHistorySha256");
            if(p.optBoolean("signingHistoryReadable")&&history!=null) box.addView(text("서명 이력 "+history.length()+"개 · OS 보고",12,MUTED));
            JSONObject policy=p.optJSONObject("factoryResetPolicy");
            if(policy!=null&&"UNEXPECTED_NON_SYSTEM".equals(policy.optString("outcome")))
                box.addView(text("초기화 직후 정책: 예상 밖의 비시스템 앱",12,0xff865000));
            JSONObject capability=p.optJSONObject("capabilityRiskReview");
            if(capability!=null&&"REVIEW".equals(capability.optString("outcome")))
                box.addView(text("활성 권한 조합 확인 필요 · 앱을 눌러 근거 확인",12,0xff865000));
            box.addView(text(p.optBoolean("confirmedIoc")?"공개 악성 파일 해시 일치 · 조치 탭 확인":p.optBoolean("apkInspectionComplete")?"base/split APK 해시 수집됨":"APK 해시 미확인 범위 있음",12,p.optBoolean("confirmedIoc")?0xffa02627:MUTED));
            long malwareHits=p.optLong("malwareReferenceMatchCount",0);
            box.addView(text(malwareHits>0?"악성·감시 자료 "+malwareHits+"건 일치 · 출처·설치 목적 확인":
                    p.optBoolean("malwareInspectionComplete")?"선택된 악성 파일 자료 대조 완료 · 일치 없음":"악성 파일 자료 대조에 미확인 범위 있음",12,malwareHits>0?0xff865000:MUTED));
            box.setOnClickListener(v->showPackage(p)); appList.addView(box);
        }
        LinearLayout pages=row();
        if(appPage>0) weighted(pages,button("이전 30개",()->{appPage--;fillApps();},false));
        if(end<matches.size()) weighted(pages,button("다음 30개",()->{appPage++;fillApps();},false));
        appList.addView(pages);
    }

    private void showPackage(JSONObject p) {
        String detail;
        try { detail=p.toString(2); } catch(Exception e) { detail=p.toString(); }
        ScrollView scroll=new ScrollView(this); TextView t=text(detail,13,INK); t.setPadding(dp(18),dp(12),dp(18),dp(12)); t.setTextIsSelectable(true); scroll.addView(t);
        new AlertDialog.Builder(this).setTitle(p.optString("label",p.optString("packageName"))).setView(scroll)
            .setPositiveButton("앱 설정 열기",(d,w)->openIntent(new Intent(Settings.ACTION_APPLICATION_DETAILS_SETTINGS,Uri.parse("package:"+p.optString("packageName")))))
            .setNegativeButton("닫기",null).show();
    }

    private void remediation() {
        if(session.running) { results();return; }
        if(session.remediationBusy) { section("조치 전후 확인 중","현재 앱 파일 또는 조치 결과를 확인하고 있습니다. 완료 후 화면을 갱신합니다.");return; }
        section("확인하고 바로 조치하기","진행 중인 흐름에서는 설정에서 돌아오면 다시 검사합니다. 중단한 흐름은 새 점검을 시작해야 합니다. 자동 삭제 진행 중에는 각 앱의 제거 여부를 확인하고 다음 대상으로 이어지며, 마지막에 전체 재검사합니다. 취소하거나 제거를 확인하지 못하면 진행을 멈춥니다. 설정 화면을 열었다는 이유만으로 해결 완료라고 표시하지 않습니다. 앱 데이터가 삭제되는 제거 작업은 Android 확인창에서 승인하세요.");
        postResetModeControl();
        if(!session.blockedRemovalPackage.isEmpty()) {
            section("삭제가 확인되지 않은 앱",session.blockedRemovalPackage+"\n"+session.blockedRemovalDetail);
            actionCard("검출 앱 정보 확인",new RemediationAction(RemediationAction.Kind.APPS,session.blockedRemovalPackage,"",""),true);
            actionCard("관리자 권한 때문에 삭제가 막힌 경우",new RemediationAction(RemediationAction.Kind.SECURITY),false);
            content.addView(button("새 점검으로 다시 시작",this::startFresh,true));
        }
        ScanReport report=session.report;
        if(report!=null) {
            for(int i=0;i<report.inventory.length();i++) {
                JSONObject row=report.inventory.optJSONObject(i);
                if(!RemediationController.canRemove(row,getPackageName())) continue;
                boolean legacy=false;
                RemediationAction remove=new RemediationAction(RemediationAction.Kind.UNINSTALL,row.optString("packageName"),(legacy?"ioc.":"malware.app.")+row.optString("packageName"),legacy?"ALERT":"WARN");
                actionCard("공개 파일 자료 일치 · "+row.optString("label"),remove,true);
            }
            Set<String> shown=new HashSet<>();
            List<Finding> sorted=new ArrayList<>(report.findings);Collections.sort(sorted,(a,b)->Integer.compare(rank(a.status),rank(b.status)));
            for(Finding finding:sorted) {
                if(finding.status!=Finding.Status.ALERT&&finding.status!=Finding.Status.WARN) continue;
                RemediationAction action=RemediationAction.forFinding(finding);
                if(action!=null&&shown.add(action.id())) actionCard(finding.title,action,false);
            }
        }
        section("갤럭시 공식 기능으로 추가 검사","삼성 앱 보호·Members 진단·자동 차단 상태는 이 앱에서 대신 확인할 수 없습니다. 해당 화면에서 직접 실행하세요. 삼성 앱을 열 수 없는 기기는 기본 설정으로 이동합니다.");
        for(RemediationAction.Kind kind:new RemediationAction.Kind[]{RemediationAction.Kind.DEVICE_CARE,RemediationAction.Kind.MEMBERS,
                RemediationAction.Kind.AUTO_BLOCKER,RemediationAction.Kind.UPDATE,RemediationAction.Kind.UNKNOWN_SOURCES,RemediationAction.Kind.PLAY_PROTECT}) {
            RemediationAction action=new RemediationAction(kind);actionCard(action.label(),action,false);
        }
        JSONArray log=session.logSnapshot();
        section("이번 실행의 조치 기록","현재 사용자 프로필에서 다시 관측한 결과입니다. 앱 제거 또는 설정 변경이 OS·펌웨어·다른 프로필까지 복구했다는 뜻은 아닙니다.");
        if(log.length()==0) content.addView(text("아직 조치 기록이 없습니다.",14,MUTED));
        for(int i=log.length()-1;i>=Math.max(0,log.length()-12);i--) {
            JSONObject entry=log.optJSONObject(i);if(entry==null) continue;
            LinearLayout box=card();
            box.addView(text(RemediationRules.outcomeLabel(entry.optString("outcome")),16,INK));
            box.addView(text(new SimpleDateFormat("HH:mm:ss",Locale.KOREA).format(new Date(entry.optLong("time")))+" · "+entry.optString("action"),12,MUTED));
            box.addView(text(entry.optString("detail"),13,MUTED));content.addView(box);
        }
    }
    private void actionCard(String title,RemediationAction action,boolean primary) {
        LinearLayout box=card();TextView h=text(title,17,INK);h.setTypeface(null,Typeface.BOLD);box.addView(h);
        box.addView(text(action.instruction(),13,MUTED));box.addView(button(action.label(),()->beginRemediation(action),primary));content.addView(box);
    }
    private void beginRemediation(RemediationAction action) {
        beginRemediation(action,false);
    }
    private void beginRemediation(RemediationAction action,boolean automatic) {
        if(session.running||session.remediationBusy||session.catalogBusy||session.pendingRemediation!=null) {toast("현재 점검·조치가 끝난 뒤 다시 눌러 주세요.");return;}
        if(action.kind!=RemediationAction.Kind.UNINSTALL) {launchRemediation(action);return;}
        if(session.cancelled.get()) {toast("중단한 흐름에서는 삭제를 진행하지 않습니다. 새 점검으로 다시 시작하세요.");return;}
        JSONObject row=RemediationController.findPackage(session.report,action.packageName);
        if(!RemediationController.canRemove(row,getPackageName())) {toast("현재 검사에서 삭제 가능한 정확 일치 근거를 찾지 못했습니다.");return;}
        session.attemptedRemoval(action.packageName);
        session.removalPreflightStarted(action);render();
        final android.content.Context app=getApplicationContext();
        session.worker.execute(()->{
            String error=null;
            try {RemediationController.preflightUninstall(app,row);}catch(Exception e){error=e.getMessage()==null?e.getClass().getSimpleName():e.getMessage();}
            final String failure=error;
            runOnUiThread(()->{
                session.remediationBusy=false;
                if(session.cancelled.get()) {
                    session.logRemediation(action.id(),"PREFLIGHT_BLOCKED","중단 요청으로 Android 삭제 화면을 열지 않았습니다.");session.cancel();return;
                }
                if(automatic&&(!session.automaticRemovalPrompts||session.automaticPromptsPaused)) {
                    session.pauseAutomaticRemoval("자동 조치가 중지되어 Android 삭제 화면을 열지 않았습니다.");
                    session.logRemediation(action.id(),"PREFLIGHT_BLOCKED","자동 진행 중지 상태를 유지합니다.");session.announce();return;
                }
                if(failure!=null) {
                    session.blockAutomaticRemoval(action.packageName,failure);session.logRemediation(action.id(),"PREFLIGHT_BLOCKED",failure);
                    session.announce();if(resumed&&!isFinishing()&&!isDestroyed()) {toast(failure);render();}return;
                }
                if(!resumed||isFinishing()||isDestroyed()) {
                    session.deferRemovalUntilForeground(action.packageName);session.announce();return;
                }
                launchRemediation(action);
            });
        });
    }
    private void launchRemediation(RemediationAction action) {
        session.pendingRemediation=action;session.leftForRemediation=false;
        try {
            startActivity(RemediationController.intent(this,action));
            if(action.kind==RemediationAction.Kind.UNINSTALL) session.removalPromptOpened(action);
            session.logRemediation(action.id(),"SCREEN_OPENED",action.instruction());
            toast(action.instruction());
        } catch(Exception first) {
            if(action.kind!=RemediationAction.Kind.UNINSTALL&&action.kind!=RemediationAction.Kind.SERVICE) {
                try {startActivity(new Intent(Settings.ACTION_SETTINGS));session.logRemediation(action.id(),"SCREEN_OPENED","전용 화면을 열지 못해 기본 설정으로 이동했습니다. "+action.instruction());toast(action.instruction());return;}
                catch(Exception ignored) { }
            }
            session.pendingRemediation=null;session.leftForRemediation=false;
            if(action.kind==RemediationAction.Kind.UNINSTALL) session.removalLaunchFailed(action,"Android 삭제 화면을 열 수 없습니다. 앱 설정에서 제한을 확인하세요.");
            session.logRemediation(action.id(),"OPEN_FAILED",first.getClass().getSimpleName());toast("이 기기에서 해당 화면을 열 수 없습니다.");render();
        }
    }

    private void guide() {
        section("실행하면 한 번에 진행", "앱을 열면 자료 확인 → 전체 검사 → 검출 앱 조치 → 재확인 → 결과 정리를 이어갑니다. 같은 점검 중의 회전·백그라운드 복귀는 중복 검사를 시작하지 않습니다. Android 삭제 승인만 필요한 순간에 표시하며, 취소·중단·검증 실패 시 다음 삭제 안내를 멈춥니다. 설정 권한 변경과 삼성 공식 진단은 결과의 다음 항목 버튼에서 직접 확인합니다.");
        postResetModeControl();catalogControls();
        section("공장 초기화 직후 사용","초기화 후 앱·설정 백업을 복원하기 전에 이 앱으로 검사하세요. 초기화 직후 모드는 기본으로 켜져 있습니다. 알려진 악성·감시 자료와 정확히 일치한 일반 앱은 재검증 후 Android 삭제 승인창으로 이어집니다. 여러 앱은 순서대로 처리하고 마지막에 재검사합니다. 삭제 취소·차단·검증 실패 시 자동 진행을 멈춥니다. 시스템 앱·이 앱은 자동 제거 대상에서 제외합니다.");
        section("이 앱이 하는 일","OS가 공개하는 정보, 루팅·후킹 흔적, 설치된 base/split APK의 실제 SHA-256·암호학적 서명, 접근성·관리자·인증서·네트워크 설정을 확인합니다. 지원 기기에서는 임시 키 증명을 만들고 공개 루트·앱 식별자·challenge·OS 표시값·내장 폐기 목록과 대조합니다.");
        section("결과를 읽는 방법","‘중요 징후’는 우선 확인해야 할 관측입니다. ‘확인 필요’는 정상 사용에서도 생길 수 있습니다. ‘미발견’은 확인한 범위에서 흔적을 찾지 못했다는 뜻입니다. ‘확인 불가’는 미지원·권한 제한·미실시 등으로 결론을 내리지 않았다는 뜻입니다. 커스텀 ROM과 루팅 자체가 악성 또는 불법이라는 판정은 하지 않습니다.");
        section("자동 악성·감시 파일 검사","ClamAV Android 해시 서명, ESET Android 공개 지표, Echap 감시 도구 자료와 MVT 지표를 사용합니다. 설치 APK 전체와 직접 압축된 내부 파일을 MD5·SHA-1·SHA-256으로 대조합니다. ClamAV 전체 엔진·바이트 패턴·실행 행위 분석·학습 모델은 포함하지 않습니다. 별도로 활성 권한 조합을 확인하지만, 미지 변종 탐지 성능을 검증한 백신은 아닙니다. 감시 도구의 동의된 사용도 검출될 수 있어 새 참조 일치는 확인 필요로 표시합니다.");
        section("검사 범위와 자료 갱신","중첩 압축은 내부까지 재귀 검사하지 않으며, 암호화·미지원 ZIP·과도한 압축비·크기·시간·취소는 미확인으로 남깁니다. 기본 자료와 별도로 앱 실행 시 Wi-Fi에서 서명된 자료 업데이트를 확인합니다. 이 안내 화면에서 자동 확인을 끄거나 지금 확인·서명 파일 가져오기를 사용할 수 있습니다. 파일 업로드는 하지 않습니다. 업데이트 게시자가 새 자료를 배포해야 탐지 자료도 바뀝니다. 삼성 앱 보호와 Play Protect에서도 최신 검사를 실행할 수 있습니다.");
        section("자료와 출처","기본 내장 참조 서명 "+MalwareCatalog.ENTRY_COUNT+"개 · 구성일 "+MalwareCatalog.SNAPSHOT_DATE+". 서명 수는 서로 다른 악성 앱 수나 탐지율을 뜻하지 않습니다. 개별 원자료 날짜·선정 규칙·라이선스는 결과 JSON의 malwareDatabase.catalog 및 공개 소스의 docs/antivirus.md에 기록합니다.");
        content.addView(button("Play 스토어 열기",this::openPlayStore,false));
        section("공장 초기화와 순정 펌웨어","공장 초기화는 사용자 데이터·앱을 지우는 작업입니다. 변조된 시스템을 제조사 원본과 같게 만들었다는 증명은 아닙니다. 제조사 정식 펌웨어·모델별 기준과 대조하는 검증이 추가로 필요합니다. 이 앱은 초기화, 루팅, 부트로더 잠금 변경을 수행하지 않습니다.");
        section("하드웨어 확인","센서·메모리·모델 정보는 OS가 보고한 내용입니다. 내부 부품의 정품 여부, 몰래 추가된 장치, 베이스밴드·주변 장치 펌웨어는 일반 앱으로 완전히 검증할 수 없습니다. 제조사 공식 진단과 서비스센터의 실물 점검이 필요합니다.");
        section("하드웨어 키 증명의 한계","공식 Google 루트·앱 서명·버전·challenge를 대조하더라도 침해된 기기 안의 결과는 속을 수 있습니다. 내장 폐기 목록은 수집 시점의 스냅샷이며 실시간 확인이 아닙니다. 외부 검증 서버, 제조사 원본 부팅 키, 삼성 Knox 원격 검증은 연결하지 않았습니다. 내장 자료의 시각·유효 범위·확인 불가 항목을 보고서에 남깁니다.");
        section("참고 보고서 비교","같은 모델의 신뢰할 수 있는 기준 기기에서 저장한 JSON을 선택하면 빌드·앱 버전·서명과, 양쪽 모두 완전하게 읽은 base/split APK 해시의 차이를 확인합니다. 선택한 파일의 진위나 제조사 기준 여부는 인증하지 않습니다. 정상 업데이트·지역·split 배포 구성 차이도 생길 수 있습니다. 가져온 보고서로 앱 삭제를 실행하지 않습니다.");
        content.addView(button("참고 JSON과 현재 결과 비교",this::chooseReference,false));
        section("개인정보·권한","검사 자료 다운로드를 위한 인터넷 권한을 사용합니다. 광고·분석 SDK는 없으며 앱 목록·APK·보고서를 전송하지 않습니다. 다운로드 서버는 접속 IP 등 일반 연결 정보를 볼 수 있습니다. 현재 프로필의 앱 목록·네트워크 상태를 읽고, 정확 지표 일치 앱의 삭제 확인창을 요청하는 권한을 사용합니다. 외부 삼성 앱·웹 안내는 사용자가 누를 때 엽니다. 보고서 저장을 누르면 임시 사본을 앱 전용 캐시에 두고 저장 후 지웁니다. 앱 목록·인증서가 들어 있는 보고서를 공개하지 마세요. IMEI·일련번호·연락처·사진·계정 비밀번호는 수집하지 않습니다.");
        section("기존 도구와 공개 검증 절차","RootBeer·Key Attestation·Auditor·App Manager·MVT의 공개 자료와 삼성 Knox·Phonecheck·Blancco·iVerify·Zimperium의 공개 절차를 참고했습니다. 상용 서비스의 비공개 엔진이나 인증 능력을 구현했다고 주장하지 않습니다. APK 서명은 Apache-2.0의 AOSP Android16 QPR2 apksig 소스로 API26–36을 모델링합니다. 미래 플랫폼과 SDK 범위가 모호한 경우는 확인 불가로 남깁니다. 기존 MVT IOC는 MIT 라이선스이며, 추가 백신·감시 자료에는 각 출처의 GPL-2.0-only·BSD-2-Clause·CC BY 4.0·MIT 조건을 적용합니다. 자료별 출처와 고지를 앱 자산과 소스에 보존했습니다.");
        content.addView(button("Android 공식 키 증명 안내",()->openUrl("https://developer.android.com/privacy-and-security/security-key-attestation"),false));
        content.addView(button("외부 키 증명 검증기 자료",()->openUrl("https://github.com/android/keyattestation"),false));
        content.addView(button("갤럭시 공식 앱 보호 안내",()->openUrl("https://www.samsungsvc.co.kr/solution/618789"),false));
        content.addView(text("RefurbCheck 1.4.0 · 자체 코드는 MIT · 참조 자료는 각각 GPL-2.0-only/BSD-2-Clause/CC BY 4.0/MIT\nAndroid 8.0 이상 · 공식 제조사 또는 보안 인증기관의 제품이 아닙니다.",12,MUTED));
    }

    private void exportReport() {
        if(session.report==null||session.running||session.remediationBusy) { toast("먼저 점검을 완료하세요."); return; }
        if(session.exportBusy) {toast("저장할 보고서를 준비 중입니다.");return;}
        try { session.pendingExport=session.report.toJson().toString(2); } catch(Exception e) { toast("보고서를 만들지 못했습니다."); return; }
        final byte[] payload=session.pendingExport.getBytes(StandardCharsets.UTF_8);
        if(payload.length>8*1024*1024) {toast("보고서가 8MiB 한도를 넘었습니다. 현재 화면의 필요한 근거를 확인하세요.");session.pendingExport=null;return;}
        session.exportBusy=true;
        session.worker.execute(()->{
            try {
                try(FileOutputStream out=new FileOutputStream(exportCache())) {out.write(payload);out.getFD().sync();}
                runOnUiThread(()->{
                    session.exportBusy=false;
                    if(isFinishing()||isDestroyed()) {session.announce();return;}
                    Intent i=new Intent(Intent.ACTION_CREATE_DOCUMENT);i.addCategory(Intent.CATEGORY_OPENABLE);i.setType("application/json");
                    i.putExtra(Intent.EXTRA_TITLE,"RefurbCheck-"+new SimpleDateFormat("yyyyMMdd-HHmmss",Locale.US).format(new Date())+".json");
                    try {startActivityForResult(i,EXPORT);}catch(Exception e){session.pendingExport=null;exportCache().delete();toast("파일 저장 앱을 열 수 없습니다.");}
                });
            } catch(Exception e) {session.exportBusy=false;session.pendingExport=null;exportCache().delete();runOnUiThread(()->toast("저장용 사본을 만들지 못했습니다. 저장 공간을 확인하세요."));}
        });
    }
    private File exportCache() {return new File(getCacheDir(),"pending-refurbcheck-report.json");}
    private void chooseReference() {
        if(session.report==null||session.running) { toast("먼저 점검을 완료하세요."); return; }
        Intent i=new Intent(Intent.ACTION_OPEN_DOCUMENT); i.addCategory(Intent.CATEGORY_OPENABLE); i.setType("*/*");
        i.putExtra(Intent.EXTRA_MIME_TYPES,new String[]{"application/json","text/plain","application/octet-stream"});
        try { startActivityForResult(i,REFERENCE); } catch(Exception e) { toast("파일 선택 앱을 열 수 없습니다."); }
    }
    @Override protected void onActivityResult(int request,int result,Intent data) {
        super.onActivityResult(request,result,data);
        if(result!=RESULT_OK||data==null||data.getData()==null) {
            if(request==EXPORT) {session.pendingExport=null;exportCache().delete();}
            return;
        }
        Uri uri=data.getData();
        if(request==EXPORT) {
            session.pendingExport=null;
            final File cached=exportCache();
            session.worker.execute(()->{
                try {
                    if(!cached.isFile()||cached.length()==0||cached.length()>8*1024*1024) throw new java.io.IOException("보고서 사본을 확인할 수 없습니다.");
                    try(InputStream in=new FileInputStream(cached);OutputStream out=getContentResolver().openOutputStream(uri,"wt")) {
                        if(out==null) throw new java.io.IOException();byte[] buffer=new byte[8192];int n;long bytes=0;
                        while((n=in.read(buffer))!=-1) {bytes+=n;if(bytes>8*1024*1024) throw new java.io.IOException();out.write(buffer,0,n);}
                        out.flush();
                    }
                    cached.delete();
                    runOnUiThread(()->toast("결과 JSON을 저장했습니다."));
                } catch(Exception e) { runOnUiThread(()->toast("저장하지 못했습니다. 다른 폴더를 선택하세요.")); }
            });
        } else if(request==CATALOG) {
            session.updateCatalog(this,uri);
        } else if(request==REFERENCE) {
            final ScanReport current=session.report;
            if(current==null) { toast("현재 점검 결과가 없습니다. 점검 완료 후 다시 비교하세요."); return; }
            toast("참고 보고서를 읽고 있습니다.");
            session.worker.execute(()->{
                try(InputStream in=getContentResolver().openInputStream(uri)) {
                    if(in==null) throw new java.io.IOException(); ByteArrayOutputStream bytes=new ByteArrayOutputStream(); byte[] buf=new byte[8192]; int n;
                    while((n=in.read(buf))!=-1) { if(bytes.size()+n>8*1024*1024) throw new IllegalArgumentException("8MB 이하의 JSON만 선택하세요."); bytes.write(buf,0,n); }
                    String comparison=BaselineComparator.compare(ReportJson.parse(bytes.toByteArray()),current.toJson());
                    runOnUiThread(()->longDialog("참고 보고서 비교",comparison));
                } catch(Exception e) { runOnUiThread(()->toast(e instanceof IllegalArgumentException?e.getMessage():"유효한 RefurbCheck JSON을 읽지 못했습니다.")); }
            });
        }
    }
    private void longDialog(String title,String message) {
        if(isFinishing()||isDestroyed()) return;
        ScrollView s=new ScrollView(this); TextView t=text(message,14,INK); t.setPadding(dp(20),dp(12),dp(20),dp(12)); t.setTextIsSelectable(true); s.addView(t);
        new AlertDialog.Builder(this).setTitle(title).setView(s).setPositiveButton("닫기",null).show();
    }
    private void openPlayStore() {
        Intent i=getPackageManager().getLaunchIntentForPackage("com.android.vending");
        if(i==null) longDialog("Google Play 확인","Google Play 스토어를 찾을 수 없습니다. 제조사에서 제공하는 보안 검사 도구를 확인하세요.");
        else { toast("Play 스토어에서 프로필 → Play Protect → 검사를 선택하세요."); openIntent(i); }
    }
    private void openUrl(String url) { openIntent(new Intent(Intent.ACTION_VIEW,Uri.parse(url))); }
    private void openIntent(Intent i) { try { startActivity(i); } catch(Exception e) { toast("이 기기에서 해당 화면을 열 수 없습니다."); } }
    private void section(String heading,String message) { LinearLayout c=card(); TextView h=text(heading,18,INK);h.setTypeface(null,Typeface.BOLD);c.addView(h);TextView t=text(message,14,MUTED);margin(t,0,8,0,0);c.addView(t);content.addView(c); }
    private TextView text(String s,int size,int color) { TextView t=new TextView(this);t.setText(s);t.setTextSize(size);t.setTextColor(color);t.setLineSpacing(dp(3),1);return t; }
    private Button button(String label,Runnable action,boolean primary) {
        Button b=new Button(this); b.setText(label);b.setTextSize(13);b.setAllCaps(false);b.setTextColor(primary?Color.WHITE:INK);b.setMinHeight(dp(48));b.setMinimumHeight(dp(48));b.setPadding(dp(8),dp(6),dp(8),dp(6));b.setBackground(bg(primary?TEAL:0xffe2e9ed,10));b.setOnClickListener(v->action.run());margin(b,0,4,0,6);return b;
    }
    private LinearLayout column() { LinearLayout l=new LinearLayout(this);l.setOrientation(LinearLayout.VERTICAL);return l; }
    private LinearLayout row() { LinearLayout l=new LinearLayout(this);l.setOrientation(LinearLayout.HORIZONTAL);l.setGravity(Gravity.CENTER_VERTICAL);return l; }
    private LinearLayout card() { LinearLayout l=column();l.setPadding(dp(16),dp(14),dp(16),dp(14));l.setBackground(bg(Color.WHITE,14));margin(l,0,0,0,10);return l; }
    private GradientDrawable bg(int color,int radius) { GradientDrawable d=new GradientDrawable();d.setColor(color);d.setCornerRadius(dp(radius));return d; }
    private void weighted(LinearLayout parent,View v) { LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(0,-2,1);p.setMargins(dp(2),dp(3),dp(2),dp(3));parent.addView(v,p); }
    private void margin(View v,int l,int t,int r,int b) { LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(-1,-2);p.setMargins(dp(l),dp(t),dp(r),dp(b));v.setLayoutParams(p); }
    private int dp(int n) { return (int)(getResources().getDisplayMetrics().density*n+.5f); }
    private void toast(String s) { Toast.makeText(this,s,Toast.LENGTH_LONG).show(); }
    private static int rank(Finding.Status s) { switch(s) { case ALERT:return 0;case WARN:return 1;case UNKNOWN:return 2;case INFO:return 3;default:return 4; } }
    private static String statusLabel(Finding.Status s) { switch(s) { case ALERT:return "중요 징후";case WARN:return "확인 필요";case UNKNOWN:return "확인 불가";case PASS:return "해당 항목 확인";default:return "참고 관측"; } }
    private static int statusColor(Finding.Status s) { switch(s) { case ALERT:return 0xffa02627;case WARN:return 0xff865000;case UNKNOWN:return 0xff615780;default:return TEAL; } }
}
