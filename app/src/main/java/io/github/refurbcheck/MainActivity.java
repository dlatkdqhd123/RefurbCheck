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
    private static final int EXPORT=100, REFERENCE=101;
    private final ScanSession session=ScanSession.INSTANCE;
    private LinearLayout root,content,appList;
    private TextView liveStage;
    private int selectedTab=0,filter=0,appPage=0;
    private boolean allApps=false,wasRunning=false,resumed=false,automaticPromptPosted=false;
    private String query="";

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        if(saved!=null) selectedTab=saved.getInt("tab");
        session.automaticRemovalPrompts=getPreferences(MODE_PRIVATE).getBoolean("postResetRemovalMode",true);
        session.listener=this;
        render();
        if(session.report==null&&!session.running) session.start(this);
    }
    @Override protected void onSaveInstanceState(Bundle state) {
        super.onSaveInstanceState(state); state.putInt("tab",selectedTab);
    }
    @Override protected void onResume() {
        super.onResume();resumed=true;session.listener=this;
        if(session.pendingRemediation!=null&&session.leftForRemediation) session.returnedFromRemediation(this);
        changed();
    }
    @Override protected void onPause() {
        resumed=false;
        if(session.pendingRemediation!=null) session.leftForRemediation=true;
        super.onPause();
    }
    @Override protected void onDestroy() { if(session.listener==this) session.listener=null; super.onDestroy(); }
    @Override public void changed() {
        if(isFinishing()||isDestroyed()) return;
        if(wasRunning&&session.running&&liveStage!=null) { liveStage.setText(session.stage); return; }
        render();
    }

    private void render() {
        wasRunning=session.running;
        liveStage=null;
        root=column(); root.setBackgroundColor(BG);
        root.setPadding(dp(18),dp(16),dp(18),dp(8));
        if(android.os.Build.VERSION.SDK_INT>=35) root.setOnApplyWindowInsetsListener((v,insets)->{
            android.graphics.Insets bars=insets.getInsets(android.view.WindowInsets.Type.systemBars());
            v.setPadding(dp(18)+bars.left,dp(16)+bars.top,dp(18)+bars.right,dp(8)+bars.bottom); return insets;
        });
        setContentView(root);
        TextView eyebrow=text("REFURBCHECK  ·  1.2.0",11,TEAL); eyebrow.setLetterSpacing(.13f); root.addView(eyebrow);
        TextView title=text("리퍼폰 점검",27,INK); title.setTypeface(null,Typeface.BOLD); root.addView(title);
        TextView subtitle=text("갤럭시 · 증거 확인과 보안 조치",13,MUTED); margin(subtitle,0,4,0,12); root.addView(subtitle);
        ScrollView sc=new ScrollView(this); sc.setFillViewport(false);
        content=column(); content.setPadding(0,0,0,dp(12)); sc.addView(content);
        root.addView(sc,new LinearLayout.LayoutParams(-1,0,1));
        if(selectedTab==0) results(); else if(selectedTab==1) apps(); else if(selectedTab==2) remediation(); else guide();
        LinearLayout nav=row(); String[] tabs={"결과","앱","조치","안내·비교"};
        for(int i=0;i<tabs.length;i++) {
            final int n=i; Button b=button(tabs[i],()->{selectedTab=n;render();},i==selectedTab);
            LinearLayout.LayoutParams p=new LinearLayout.LayoutParams(0,dp(52),1); p.setMargins(dp(2),dp(4),dp(2),0); nav.addView(b,p);
        }
        root.addView(nav);
        maybeStartAutomaticRemoval();
    }

    private void maybeStartAutomaticRemoval() {
        if(!resumed||automaticPromptPosted||session.running||session.remediationBusy||session.pendingRemediation!=null
                ||isFinishing()||isDestroyed()) return;
        JSONObject next=session.nextAutomaticRemoval(getPackageName());if(next==null) return;
        automaticPromptPosted=true;
        session.main.post(()->{
            automaticPromptPosted=false;
            if(!resumed||session.running||session.remediationBusy||session.pendingRemediation!=null||isFinishing()||isDestroyed()) return;
            JSONObject current=session.nextAutomaticRemoval(getPackageName());if(current==null) return;
            String pkg=current.optString("packageName");session.attemptedRemoval(pkg);
            boolean legacy=RemediationRules.eligible(current,getPackageName());
            RemediationAction action=new RemediationAction(RemediationAction.Kind.UNINSTALL,pkg,
                    (legacy?"ioc.":"malware.app.")+pkg,legacy?"ALERT":"WARN");
            session.logRemediation(action.id(),"AUTO_REMOVAL_PREFLIGHT","초기화 직후 모드: 공개 파일 자료와 일치한 일반 앱을 재검증합니다. Android에서 삭제를 승인해야 제거됩니다.");
            beginRemediation(action,true);
        });
    }

    private void postResetModeControl() {
        LinearLayout box=card();
        Switch mode=new Switch(this);mode.setText("초기화 직후 · 검출 앱 삭제 확인 자동 진행");
        mode.setTextSize(14);mode.setTextColor(INK);mode.setChecked(session.automaticRemovalPrompts);box.addView(mode);
        box.addView(text("직접 설치한 감시·관리 앱이 없는 기기를 위한 모드입니다. 정확한 파일 지표가 일치한 일반 앱만 삭제 직전에 다시 확인하고 Android 승인창을 엽니다. 취소하면 자동 진행을 멈춥니다.",12,MUTED));
        mode.setOnCheckedChangeListener((button,checked)->{
            session.automaticRemovalPrompts=checked;
            getPreferences(MODE_PRIVATE).edit().putBoolean("postResetRemovalMode",checked).apply();
            if(!checked) session.automaticPromptsPaused=true;
            else {session.automaticPromptsPaused=false;maybeStartAutomaticRemoval();}
        });
        content.addView(box);
    }

    private void results() {
        if(session.running) {
            LinearLayout box=card();
            TextView h=text("종합 점검 중",21,INK); h.setTypeface(null,Typeface.BOLD); box.addView(h);
            liveStage=text(session.stage,15,MUTED); margin(liveStage,0,12,0,12); box.addView(liveStage);
            ProgressBar p=new ProgressBar(this,null,android.R.attr.progressBarStyleHorizontal); p.setIndeterminate(true); box.addView(p,new LinearLayout.LayoutParams(-1,dp(8)));
            box.addView(text("화면을 회전해도 점검은 계속됩니다. APK 읽기는 최대 3분·8GiB 예산으로 실행하며, 미검사 파일은 확인 불가로 남깁니다. 키 증명 요청 중에는 중단 처리에 시간이 걸릴 수 있습니다.",13,MUTED));
            box.addView(button("검사 중단 · 완료한 근거 보기",session::cancel,false));
            content.addView(box); postResetModeControl();limitation(); return;
        }
        ScanReport r=session.report;
        if(r==null) { content.addView(button("종합 점검 시작",()->session.start(this),true)); limitation(); return; }
        LinearLayout hero=card();
        int alerts=r.count(Finding.Status.ALERT),warnings=r.count(Finding.Status.WARN),unknown=r.count(Finding.Status.UNKNOWN);
        TextView label=text("이번 점검 결과",12,MUTED); hero.addView(label);
        TextView verdict=text(r.verdict(),23,alerts>0?0xffa02627:warnings>0?0xff865000:INK); verdict.setTypeface(null,Typeface.BOLD); margin(verdict,0,8,0,10); hero.addView(verdict);
        hero.addView(text("중요 징후 "+alerts+"  ·  확인 필요 "+warnings+"  ·  확인 불가 "+unknown,14,INK));
        hero.addView(text("검사 "+r.findings.size()+"항목  |  "+new SimpleDateFormat("MM.dd HH:mm",Locale.KOREA).format(new Date(r.completedAt)),12,MUTED));
        JSONObject coverage=r.evidence.optJSONObject("apkCoverage");
        if(coverage!=null) {
            hero.addView(text("APK 해시 "+coverage.optInt("filesHashed")+" / "+coverage.optInt("filesDiscovered")+"개 · 공개 지표 일치 "+coverage.optInt("iocMatchingPackages")+"개 앱",13,INK));
            hero.addView(text(coverage.optBoolean("complete")?"공개 APK 검사 범위 완료 · 기기 전체 안전 판정 아님":"APK 검사에 미확인 범위가 있습니다. 상세 근거를 확인하세요.",12,MUTED));
        }
        JSONObject malware=r.evidence.optJSONObject("malwareCoverage");
        if(malware!=null) {
            hero.addView(text("악성·감시 자료 대조 · APK "+malware.optInt("wholeFilesCompared")+"개 / 내부 파일 "+malware.optLong("entriesHashed")+"개 · 일치 "+malware.optInt("matchingPackages")+"개 앱",13,INK));
            hero.addView(text(malware.optBoolean("complete")?"직접 파일 검사 범위 완료 · 알려지지 않은 악성코드는 놓칠 수 있습니다.":"악성 파일 검사에 미확인 범위가 있습니다. 아래 상세 결과를 확인하세요.",12,MUTED));
        }
        content.addView(hero); postResetModeControl();limitation();
        LinearLayout actions=row(); weighted(actions,button("다시 점검",()->session.start(this),true)); weighted(actions,button("결과 JSON 저장",this::exportReport,false)); content.addView(actions);
        content.addView(button("보안 조치와 갤럭시 진단 열기",()->{selectedTab=2;render();},true));
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
        if(f.id.startsWith("ioc.")) {
            JSONObject pkg=RemediationController.findPackage(session.report,f.id.substring(4));
            if(RemediationRules.eligible(pkg,getPackageName())) {
                RemediationAction remove=new RemediationAction(RemediationAction.Kind.UNINSTALL,pkg.optString("packageName"),f.id,f.status.name());
                details.addView(button(remove.label(),()->beginRemediation(remove),true));
            }
        }
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
            box.addView(text(p.optBoolean("confirmedIoc")?"공개 악성 파일 해시 일치 · 조치 탭 확인":p.optBoolean("apkInspectionComplete")?"base/split APK 해시 수집됨":"APK 해시 미확인 범위 있음",12,p.optBoolean("confirmedIoc")?0xffa02627:MUTED));
            long malwareHits=p.optLong("malwareReferenceMatchCount",0);
            box.addView(text(malwareHits>0?"악성·감시 자료 "+malwareHits+"건 일치 · 출처·설치 목적 확인":
                    p.optBoolean("malwareInspectionComplete")?"내장 악성 파일 자료 대조 완료 · 일치 없음":"악성 파일 자료 대조에 미확인 범위 있음",12,malwareHits>0?0xff865000:MUTED));
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
        section("확인하고 바로 조치하기","설정에서 돌아오면 다시 검사합니다. 자동 삭제 진행 중에는 각 앱의 제거 여부를 확인하고 다음 대상으로 이어지며, 마지막에 전체 재검사합니다. 취소하거나 제거를 확인하지 못하면 진행을 멈춥니다. 설정 화면을 열었다는 이유만으로 해결 완료라고 표시하지 않습니다. 앱 데이터가 삭제되는 제거 작업은 Android 확인창에서 승인하세요.");
        postResetModeControl();
        if(!session.blockedRemovalPackage.isEmpty()) {
            section("삭제가 확인되지 않은 앱",session.blockedRemovalPackage+"\n"+session.blockedRemovalDetail);
            actionCard("검출 앱 정보 확인",new RemediationAction(RemediationAction.Kind.APPS,session.blockedRemovalPackage,"",""),true);
            actionCard("관리자 권한 때문에 삭제가 막힌 경우",new RemediationAction(RemediationAction.Kind.SECURITY),false);
            content.addView(button("다시 점검하고 조치 계속",()->session.start(this),true));
        }
        ScanReport report=session.report;
        if(report!=null) {
            for(int i=0;i<report.inventory.length();i++) {
                JSONObject row=report.inventory.optJSONObject(i);
                if(!RemediationController.canRemove(row,getPackageName())) continue;
                boolean legacy=RemediationRules.eligible(row,getPackageName());
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
        if(session.running||session.remediationBusy||session.pendingRemediation!=null) {toast("현재 점검·조치가 끝난 뒤 다시 눌러 주세요.");return;}
        if(action.kind!=RemediationAction.Kind.UNINSTALL) {launchRemediation(action);return;}
        JSONObject row=RemediationController.findPackage(session.report,action.packageName);
        if(!RemediationController.canRemove(row,getPackageName())) {toast("현재 검사에서 삭제 가능한 정확 일치 근거를 찾지 못했습니다.");return;}
        session.attemptedRemoval(action.packageName);
        session.remediationBusy=true;render();
        final android.content.Context app=getApplicationContext();
        session.worker.execute(()->{
            String error=null;
            try {RemediationController.preflightUninstall(app,row);}catch(Exception e){error=e.getMessage()==null?e.getClass().getSimpleName():e.getMessage();}
            final String failure=error;
            runOnUiThread(()->{
                session.remediationBusy=false;
                if(!resumed||isFinishing()||isDestroyed()||(automatic&&!session.automaticRemovalPrompts)) {
                    session.blockAutomaticRemoval(action.packageName,"화면을 벗어났거나 자동 조치를 해제했습니다. 조치 탭에서 다시 선택하세요.");
                    session.logRemediation(action.id(),"PREFLIGHT_BLOCKED",failure==null?session.blockedRemovalDetail:failure);session.announce();return;}
                session.announce();
                if(failure!=null) {session.blockAutomaticRemoval(action.packageName,failure);selectedTab=2;session.logRemediation(action.id(),"PREFLIGHT_BLOCKED",failure);toast(failure);render();return;}
                launchRemediation(action);
            });
        });
    }
    private void launchRemediation(RemediationAction action) {
        session.pendingRemediation=action;session.leftForRemediation=false;
        try {
            startActivity(RemediationController.intent(this,action));
            session.logRemediation(action.id(),"SCREEN_OPENED",action.instruction());
            toast(action.instruction());
        } catch(Exception first) {
            if(action.kind!=RemediationAction.Kind.UNINSTALL&&action.kind!=RemediationAction.Kind.SERVICE) {
                try {startActivity(new Intent(Settings.ACTION_SETTINGS));session.logRemediation(action.id(),"SCREEN_OPENED","전용 화면을 열지 못해 기본 설정으로 이동했습니다. "+action.instruction());toast(action.instruction());return;}
                catch(Exception ignored) { }
            }
            session.pendingRemediation=null;session.leftForRemediation=false;
            if(action.kind==RemediationAction.Kind.UNINSTALL) session.blockAutomaticRemoval(action.packageName,"Android 삭제 화면을 열 수 없습니다. 앱 설정에서 제한을 확인하세요.");
            session.logRemediation(action.id(),"OPEN_FAILED",first.getClass().getSimpleName());toast("이 기기에서 해당 화면을 열 수 없습니다.");render();
        }
    }

    private void guide() {
        section("공장 초기화 직후 사용","초기화 후 앱·설정 백업을 복원하기 전에 이 앱으로 검사하세요. 초기화 직후 모드는 기본으로 켜져 있습니다. 알려진 악성·감시 자료와 정확히 일치한 일반 앱은 재검증 후 Android 삭제 승인창으로 이어집니다. 여러 앱은 순서대로 처리하고 마지막에 재검사합니다. 삭제 취소·차단·검증 실패 시 자동 진행을 멈춥니다. 시스템 앱·이 앱은 자동 제거 대상에서 제외합니다.");
        section("이 앱이 하는 일","OS가 공개하는 정보, 루팅·후킹 흔적, 설치된 base/split APK의 실제 SHA-256·암호학적 서명, 접근성·관리자·인증서·네트워크 설정을 확인합니다. 지원 기기에서는 임시 키 증명을 만들고 공개 루트·앱 식별자·challenge·OS 표시값·내장 폐기 목록과 대조합니다.");
        section("결과를 읽는 방법","‘중요 징후’는 우선 확인해야 할 관측입니다. ‘확인 필요’는 정상 사용에서도 생길 수 있습니다. ‘미발견’은 확인한 범위에서 흔적을 찾지 못했다는 뜻입니다. ‘확인 불가’는 미지원·권한 제한·미실시 등으로 결론을 내리지 않았다는 뜻입니다. 커스텀 ROM과 루팅 자체가 악성 또는 불법이라는 판정은 하지 않습니다.");
        section("자동 악성·감시 파일 검사","ClamAV Android 해시 서명, ESET Android 공개 지표, Echap 감시 도구 자료와 MVT 지표를 사용합니다. 설치 APK 전체와 직접 압축된 내부 파일을 MD5·SHA-1·SHA-256으로 대조합니다. ClamAV 전체 엔진·바이트 패턴·행위 분석·미지 변종 탐지는 포함하지 않습니다. 감시 도구의 동의된 사용도 검출될 수 있어 새 참조 일치는 확인 필요로 표시합니다.");
        section("검사 범위와 자료 갱신","중첩 압축은 내부까지 재귀 검사하지 않으며, 암호화·미지원 ZIP·과도한 압축비·크기·시간·취소는 미확인으로 남깁니다. 자료는 앱에 포함한 스냅샷이고 자동 인터넷 업데이트나 파일 업로드는 하지 않습니다. 새 자료는 앱 업데이트로 받으세요. 삼성 앱 보호와 Play Protect에서도 최신 검사를 실행할 수 있습니다.");
        section("자료와 출처","내장 참조 서명 "+MalwareCatalog.ENTRY_COUNT+"개 · 구성일 "+MalwareCatalog.SNAPSHOT_DATE+". 서명 수는 서로 다른 악성 앱 수나 탐지율을 뜻하지 않습니다. 개별 원자료 날짜·선정 규칙·라이선스는 결과 JSON의 malwareDatabase.catalog 및 공개 소스의 docs/antivirus.md에 기록합니다.");
        content.addView(button("Play 스토어 열기",this::openPlayStore,false));
        section("공장 초기화와 순정 펌웨어","공장 초기화는 사용자 데이터·앱을 지우는 작업입니다. 변조된 시스템을 제조사 원본과 같게 만들었다는 증명은 아닙니다. 제조사 정식 펌웨어·모델별 기준과 대조하는 검증이 추가로 필요합니다. 이 앱은 초기화, 루팅, 부트로더 잠금 변경을 수행하지 않습니다.");
        section("하드웨어 확인","센서·메모리·모델 정보는 OS가 보고한 내용입니다. 내부 부품의 정품 여부, 몰래 추가된 장치, 베이스밴드·주변 장치 펌웨어는 일반 앱으로 완전히 검증할 수 없습니다. 제조사 공식 진단과 서비스센터의 실물 점검이 필요합니다.");
        section("하드웨어 키 증명의 한계","공식 Google 루트·앱 서명·버전·challenge를 대조하더라도 침해된 기기 안의 결과는 속을 수 있습니다. 내장 폐기 목록은 수집 시점의 스냅샷이며 실시간 확인이 아닙니다. 외부 검증 서버, 제조사 원본 부팅 키, 삼성 Knox 원격 검증은 연결하지 않았습니다. 내장 자료의 시각·유효 범위·확인 불가 항목을 보고서에 남깁니다.");
        section("참고 보고서 비교","같은 모델의 신뢰할 수 있는 기준 기기에서 저장한 JSON을 선택하면 빌드·앱 버전·서명과, 양쪽 모두 완전하게 읽은 base/split APK 해시의 차이를 확인합니다. 선택한 파일의 진위나 제조사 기준 여부는 인증하지 않습니다. 정상 업데이트·지역·split 배포 구성 차이도 생길 수 있습니다. 가져온 보고서로 앱 삭제를 실행하지 않습니다.");
        content.addView(button("참고 JSON과 현재 결과 비교",this::chooseReference,false));
        section("개인정보·권한","인터넷 권한·광고·분석 SDK가 없습니다. 현재 프로필의 앱 목록·네트워크 상태를 읽고, 정확 지표 일치 앱의 삭제 확인창을 요청하는 권한을 사용합니다. 외부 삼성 앱·웹 안내는 사용자가 누를 때 엽니다. 보고서 저장을 누르면 임시 사본을 앱 전용 캐시에 두고 저장 후 지웁니다. 앱 목록·인증서가 들어 있는 보고서를 공개하지 마세요. IMEI·일련번호·연락처·사진·계정 비밀번호는 수집하지 않습니다.");
        section("기존 도구와 공개 검증 절차","RootBeer·Key Attestation·Auditor·App Manager·MVT의 공개 자료와 삼성 Knox·Phonecheck·Blancco·iVerify·Zimperium의 공개 절차를 참고했습니다. 상용 서비스의 비공개 엔진이나 인증 능력을 구현했다고 주장하지 않습니다. APK 서명은 Apache-2.0의 apksig-android 4.4.0을 사용하며 API 33보다 새 Android의 최종 서명 판정은 확인 불가로 남깁니다. 기존 MVT IOC는 MIT 라이선스이며, 추가 백신·감시 자료에는 각 출처의 GPL-2.0-only·BSD-2-Clause·CC BY 4.0·MIT 조건을 적용합니다. 자료별 출처와 고지를 앱 자산과 소스에 보존했습니다.");
        content.addView(button("Android 공식 키 증명 안내",()->openUrl("https://developer.android.com/privacy-and-security/security-key-attestation"),false));
        content.addView(button("Auditor 공식 안내",()->openUrl("https://attestation.app/about"),false));
        content.addView(button("갤럭시 공식 앱 보호 안내",()->openUrl("https://www.samsungsvc.co.kr/solution/618789"),false));
        content.addView(text("RefurbCheck 1.2.0 · 자체 코드는 MIT · 참조 자료는 각각 GPL-2.0-only/BSD-2-Clause/CC BY 4.0/MIT\nAndroid 8.0 이상 · 공식 제조사 또는 보안 인증기관의 제품이 아닙니다.",12,MUTED));
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
