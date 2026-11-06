package io.github.refurbcheck;

import android.content.Context;
import android.os.Handler;
import android.os.Looper;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.HashSet;
import java.util.Set;
import org.json.JSONArray;
import org.json.JSONObject;

/** Keeps a scan alive across screen rotation, without retaining an Activity. */
final class ScanSession {
    interface Listener { void changed(); }
    static final ScanSession INSTANCE=new ScanSession();
    final Handler main=new Handler(Looper.getMainLooper());
    final ExecutorService worker=Executors.newSingleThreadExecutor();
    volatile ScanReport report;
    volatile String stage="점검 준비";
    volatile boolean running;
    volatile String pendingExport;
    volatile boolean exportBusy;
    volatile boolean catalogBusy;
    volatile boolean automaticCatalogUpdates=true;
    volatile String catalogMessage="";
    private volatile long lastAutomaticCheckElapsed;
    private static final long UPDATE_CHECK_INTERVAL_MILLIS=6L*60*60*1000;
    private boolean skipNextCatalogCheck;
    final AtomicBoolean cancelled=new AtomicBoolean(false);
    volatile boolean remediationBusy;
    RemediationAction pendingRemediation;
    private RemediationAction verificationAfterScan;
    boolean leftForRemediation;
    volatile boolean automaticRemovalPrompts=true;
    boolean automaticPromptsPaused;
    String blockedRemovalPackage="",blockedRemovalDetail="";
    private final Set<String> automaticAttempts=new HashSet<>();
    private final JSONArray remediationLog=new JSONArray();
    Listener listener;
    void announce() { main.post(() -> { if(listener!=null) listener.changed(); }); }
    synchronized void start(Context context) {
        start(context,false);
    }
    private synchronized void start(Context context,boolean afterRemediation) {
        if(running||remediationBusy||catalogBusy) return;
        if(!afterRemediation) {
            automaticAttempts.clear();automaticPromptsPaused=false;
            blockedRemovalPackage="";blockedRemovalDetail="";
        }
        running=true; report=null;cancelled.set(false); stage="점검 준비"; announce();
        Context app=context.getApplicationContext();
        worker.execute(() -> {
            ScanReport value;
            JSONObject updateAttempt=new JSONObject();
            try {
                ScanEngine.Progress progress=s -> {stage=cancelled.get()?"검사 중단 처리 중":s;announce();};
                long elapsed=android.os.SystemClock.elapsedRealtime();
                boolean check=!skipNextCatalogCheck&&!afterRemediation&&automaticCatalogUpdates
                        &&(lastAutomaticCheckElapsed==0||elapsed-lastAutomaticCheckElapsed>=UPDATE_CHECK_INTERVAL_MILLIS);
                skipNextCatalogCheck=false;
                if(check&&wifiAvailable(app)&&!cancelled.get()) {
                    lastAutomaticCheckElapsed=Math.max(1,elapsed);
                    progress.update("서명된 검사 자료 업데이트 확인 중");
                    try {
                        CatalogUpdateManager.Result result=CatalogUpdateManager.downloadAndInstall(app,cancelled);
                        updateAttempt=result.diagnostics();catalogMessage=result.message;
                    } catch(Exception error) {
                        catalogMessage="업데이트를 확인하지 못했습니다. 사용 가능한 자료로 계속 검사합니다.";
                        updateAttempt.put("state","UPDATE_CHECK_FAILED").put("error",error.getClass().getSimpleName())
                                .put("latestAvailabilityConfirmed",false);
                    }
                } else updateAttempt.put("state",!automaticCatalogUpdates?"AUTOMATIC_UPDATES_DISABLED":
                        check?"NO_WIFI_OR_CANCELLED":"AUTOMATIC_CHECK_THROTTLED_OR_AFTER_REMEDIATION")
                        .put("latestAvailabilityConfirmed",false);
                value=new ScanEngine(app,automaticRemovalPrompts).scan(progress,cancelled);
                value.evidence.put("catalogUpdateAttempt",updateAttempt);
                try { GalaxyInspector.inspect(app,value); }
                catch(Exception ex) { value.add(new Finding("galaxy.unavailable","갤럭시 보안","삼성 관련 정보 확인 불가",Finding.Status.UNKNOWN,
                        ex.getClass().getSimpleName(),"설정과 삼성 공식 앱에서 지원 기능을 확인하세요.")); }
                try { ApkInspection.inspect(app,value,progress,cancelled); }
                catch(Exception ex) { value.add(new Finding("apk.unavailable","앱 파일 무결성","APK 검사가 완료되지 않았습니다",Finding.Status.UNKNOWN,
                        ex.getClass().getSimpleName(),"확인한 일부 정보만 남았습니다. 다시 검사하세요.")); }
            } catch(Exception ex) {
                value=new ScanReport();
                value.add(new Finding("scan_failure","검사 범위","검사가 완료되지 않았습니다",Finding.Status.UNKNOWN,
                    "실행 오류: "+ex.getClass().getSimpleName(),"앱을 다시 실행하고 결과가 반복되면 사용 중인 Android 버전을 확인하세요."));
            }
            if(cancelled.get()) value.add(new Finding("scan.cancelled","검사 범위","사용자가 중단한 검사",Finding.Status.UNKNOWN,
                    "중단 요청 이전에 완료한 관측만 표시합니다. 전체 검사를 완료한 결과가 아닙니다.","다시 점검을 누르면 처음부터 수집합니다."));
            RemediationAction verify=verificationAfterScan;verificationAfterScan=null;
            if(verify!=null&&verify.kind!=RemediationAction.Kind.UNINSTALL) {
                Finding after=null;for(Finding f:value.findings) if(f.id.equals(verify.findingId)) {after=f;break;}
                String outcome=RemediationRules.reobservedOutcome(verify.findingId,verify.beforeStatus,after);
                logRemediation(verify.id(),outcome,"재검사 결과: "+(after==null?"직접 확인할 수 없는 조치":after.status.name())+". 현재 프로필의 노출된 범위만 확인합니다.");
            }
            try {value.evidence.put("remediationLog",logSnapshot());value.evidence.put("cancelRequested",cancelled.get());
                value.evidence.put("postResetRemovalMode",automaticRemovalPrompts)
                        .put("silentRemoval",false).put("systemRemovalApprovalRequired",true);
            }catch(Exception ignored) { }
            value.completedAt=System.currentTimeMillis(); report=value;
            stage=cancelled.get()?"중단된 범위까지 결과 표시":"점검 완료"; running=false; announce();
        });
    }
    private static boolean wifiAvailable(Context context) {
        try {
            android.net.ConnectivityManager manager=(android.net.ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
            android.net.Network network=manager==null?null:manager.getActiveNetwork();
            android.net.NetworkCapabilities caps=network==null?null:manager.getNetworkCapabilities(network);
            return caps!=null&&caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI);
        } catch(RuntimeException error) {return false;}
    }
    void catalogUpdatePreferenceChanged() { lastAutomaticCheckElapsed=0; }
    synchronized void updateCatalog(Context context,android.net.Uri selectedFile) {
        if(running||remediationBusy||catalogBusy||pendingRemediation!=null) return;
        catalogBusy=true;catalogMessage=selectedFile==null?"검사 자료를 다운로드하고 서명을 확인하는 중입니다.":"선택한 검사 자료의 서명을 확인하는 중입니다.";
        announce();Context app=context.getApplicationContext();
        worker.execute(()->{
            boolean updated=false;
            try {
                CatalogUpdateManager.Result result;
                if(selectedFile==null) result=CatalogUpdateManager.downloadAndInstall(app,new AtomicBoolean(false));
                else try(java.io.InputStream stream=app.getContentResolver().openInputStream(selectedFile)) {
                    if(stream==null) throw new java.io.IOException("선택한 파일을 열 수 없습니다.");
                    result=CatalogUpdateManager.importUpdate(app,stream,new AtomicBoolean(false));
                }
                catalogMessage=result.message;updated=true;lastAutomaticCheckElapsed=Math.max(1,android.os.SystemClock.elapsedRealtime());
            } catch(Exception error) {
                catalogMessage="자료를 적용하지 않았습니다. 기존 자료를 유지합니다. "+error.getClass().getSimpleName()+": "+error.getMessage();
            }
            final boolean success=updated;
            main.post(()->{
                catalogBusy=false;
                if(success) {skipNextCatalogCheck=true;start(app,false);} else announce();
            });
        });
    }
    void cancel() { cancelled.set(true);stage="검사 중단 처리 중";announce(); }
    void returnedFromRemediation(Context context) {
        final RemediationAction action=pendingRemediation;
        if(action==null||!leftForRemediation) return;
        pendingRemediation=null;leftForRemediation=false;remediationBusy=true;
        logRemediation(action.id(),"SCREEN_RETURNED","화면에서 돌아왔습니다. 화면을 연 사실만으로 조치 완료를 판단하지 않습니다.");announce();
        Context app=context.getApplicationContext();
        worker.execute(()->{
            String outcome="";
            if(action.kind==RemediationAction.Kind.UNINSTALL) {
                outcome=RemediationController.removalOutcome(app,action.packageName);
                logRemediation(action.id(),outcome,
                        "패키지 "+action.packageName+"의 현재 프로필 표시 여부를 재조회했습니다. 다른 프로필·잔존 코드·기기 전체 복구는 검증하지 않습니다.");
            }
            final String observed=outcome;
            main.post(()->{
                remediationBusy=false;
                if(action.kind==RemediationAction.Kind.UNINSTALL&&automaticRemovalPrompts) {
                    if(!"PACKAGE_NOT_PRESENT".equals(observed)) {
                        automaticPromptsPaused=true;blockedRemovalPackage=action.packageName;
                        blockedRemovalDetail="앱 제거가 확인되지 않았습니다. 삭제를 취소했거나 관리자 권한 등의 제한이 있을 수 있습니다. 자동 삭제 안내를 멈췄습니다. 앱 설정과 기기 관리자 상태를 확인하세요.";
                    } else if(nextAutomaticRemoval(app.getPackageName())!=null) {
                        // Revalidate each remaining target against live files before asking Android to remove it.
                        // A final full scan follows the last target; no stale report can itself authorize removal.
                        announce();return;
                    }
                }
                verificationAfterScan=action;start(app,true);
            });
        });
    }
    JSONObject nextAutomaticRemoval(String ownPackage) {
        if(!automaticRemovalPrompts||automaticPromptsPaused||catalogBusy||report==null||cancelled.get()) return null;
        for(int i=0;i<report.inventory.length();i++) {
            JSONObject row=report.inventory.optJSONObject(i);
            if(row!=null&&!automaticAttempts.contains(row.optString("packageName"))&&RemediationController.canRemove(row,ownPackage)) return row;
        }
        return null;
    }
    void attemptedRemoval(String packageName) { automaticAttempts.add(packageName); }
    void blockAutomaticRemoval(String packageName,String detail) {
        automaticPromptsPaused=true;blockedRemovalPackage=packageName;blockedRemovalDetail=detail;
    }
    synchronized void logRemediation(String action,String outcome,String detail) {
        JSONObject o=new JSONObject();try{o.put("time",System.currentTimeMillis());o.put("action",action);o.put("outcome",outcome);o.put("detail",detail);remediationLog.put(o);}catch(Exception ignored){}
        if(report!=null)try{report.evidence.put("remediationLog",logSnapshot());}catch(Exception ignored){}
    }
    synchronized JSONArray logSnapshot() { try{return new JSONArray(remediationLog.toString());}catch(Exception e){return new JSONArray();} }
}
