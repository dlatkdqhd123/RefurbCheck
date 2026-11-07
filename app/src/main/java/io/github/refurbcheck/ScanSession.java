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

/** Keeps a complete launch-to-summary cycle alive without retaining an Activity. */
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
    private AtomicBoolean catalogCancellation;
    private JSONObject nextCatalogUpdateAttempt;
    private JSONObject catalogUpdateAttempt=new JSONObject();
    final AtomicBoolean cancelled=new AtomicBoolean(false);
    volatile boolean remediationBusy;
    volatile RemediationAction pendingRemediation;
    volatile boolean leftForRemediation;
    volatile boolean automaticRemovalPrompts=true;
    volatile boolean automaticPromptsPaused;
    volatile String blockedRemovalPackage="",blockedRemovalDetail="";
    private final Set<String> automaticAttempts=new HashSet<>();
    private JSONArray remediationLog=new JSONArray();
    private final OneRunState flow=new OneRunState();
    Listener listener;

    void announce() {
        if(cancelled.get()) refreshStage();
        main.post(() -> { if(listener!=null) listener.changed(); });
    }
    synchronized void start(Context context) { startOneRun(context); }
    synchronized void startOneRun(Context context) {
        flow.automaticMode(automaticRemovalPrompts);
        if(running||remediationBusy||catalogBusy||pendingRemediation!=null||flow.hasPendingAutomaticWork()) return;
        automaticAttempts.clear();automaticPromptsPaused=false;blockedRemovalPackage="";blockedRemovalDetail="";
        remediationLog=new JSONArray();cancelled.set(false);leftForRemediation=false;
        flow.begin(System.currentTimeMillis(),automaticRemovalPrompts);
        catalogUpdateAttempt=nextCatalogUpdateAttempt==null?new JSONObject():copyObject(nextCatalogUpdateAttempt);
        nextCatalogUpdateAttempt=null;
        startScan(context,false,null);
    }

    /** Internal rescans preserve cancellation, attempts, outcome counters and this run's identity. */
    private synchronized void startScan(Context context,boolean recheck,RemediationAction verify) {
        if(running||remediationBusy||catalogBusy||pendingRemediation!=null||cancelled.get()) return;
        running=true;report=null;stage=recheck?"조치 후 전체 재검사":"검사 자료 업데이트 확인";
        final String run=flow.runId();
        final boolean skip=skipNextCatalogCheck;skipNextCatalogCheck=false;
        if(recheck) flow.scanStarted(true);
        announce();Context app=context.getApplicationContext();
        worker.execute(() -> {
            ScanReport value;boolean completed=false;
            try {
                ScanEngine.Progress progress=s -> {
                    synchronized(ScanSession.this) {
                        if(!run.equals(flow.runId())) return;
                        stage=cancelled.get()?"검사 중단 처리 중":s;
                    }
                    announce();
                };
                if(!recheck) {
                    JSONObject update=checkCatalog(app,skip,progress);
                    synchronized(ScanSession.this) {
                        if(!run.equals(flow.runId())) return;
                        catalogUpdateAttempt=copyObject(update);
                        flow.updateFinished(update.optString("state","UPDATE_STATE_UNAVAILABLE"));
                        flow.scanStarted(false);
                    }
                }
                if(cancelled.get()) value=new ScanReport();
                else {
                    value=new ScanEngine(app,automaticRemovalPrompts).scan(progress,cancelled);
                    if(!cancelled.get()) try { GalaxyInspector.inspect(app,value); }
                    catch(Exception ex) { value.add(new Finding("galaxy.unavailable","갤럭시 보안","삼성 관련 정보 확인 불가",Finding.Status.UNKNOWN,
                            ex.getClass().getSimpleName(),"설정과 삼성 공식 앱에서 지원 기능을 확인하세요.")); }
                    if(!cancelled.get()) try { ApkInspection.inspect(app,value,progress,cancelled); }
                    catch(Exception ex) { value.add(new Finding("apk.unavailable","앱 파일 무결성","APK 검사가 완료되지 않았습니다",Finding.Status.UNKNOWN,
                            ex.getClass().getSimpleName(),"확인한 일부 정보만 남았습니다. 다시 검사하세요.")); }
                    completed=!cancelled.get();
                }
            } catch(Exception ex) {
                value=new ScanReport();
                value.add(new Finding("scan_failure","검사 범위","검사가 완료되지 않았습니다",Finding.Status.UNKNOWN,
                        "실행 오류: "+ex.getClass().getSimpleName(),"앱을 다시 실행하고 결과가 반복되면 사용 중인 Android 버전을 확인하세요."));
            }
            final ScanReport result=value;final boolean scanCompleted=completed;
            main.post(() -> finishScan(run,app.getPackageName(),result,scanCompleted,verify));
        });
    }

    private JSONObject checkCatalog(Context app,boolean skip,ScanEngine.Progress progress) throws Exception {
        JSONObject update=new JSONObject();long elapsed=android.os.SystemClock.elapsedRealtime();
        boolean check=!skip&&automaticCatalogUpdates
                &&(lastAutomaticCheckElapsed==0||elapsed-lastAutomaticCheckElapsed>=UPDATE_CHECK_INTERVAL_MILLIS);
        if(skip) {
            synchronized(this) { update=copyObject(catalogUpdateAttempt); }
            if(!update.has("state")) update.put("state","PREVIOUS_UPDATE_CHECK").put("latestAvailabilityConfirmed",false);
        } else if(check&&wifiAvailable(app)&&!cancelled.get()) {
            lastAutomaticCheckElapsed=Math.max(1,elapsed);progress.update("서명된 검사 자료 업데이트 확인 중");
            try {
                CatalogUpdateManager.Result result=CatalogUpdateManager.downloadAndInstall(app,cancelled);
                update=result.diagnostics();catalogMessage=result.message;
            } catch(Exception error) {
                catalogMessage="업데이트를 확인하지 못했습니다. 사용 가능한 자료로 계속 검사합니다.";
                update.put("state",cancelled.get()?"UPDATE_CANCELLED":"UPDATE_CHECK_FAILED")
                        .put("error",error.getClass().getSimpleName()).put("latestAvailabilityConfirmed",false);
            }
        } else update.put("state",cancelled.get()?"UPDATE_CANCELLED":!automaticCatalogUpdates?"AUTOMATIC_UPDATES_DISABLED":
                check?"NO_WIFI":"AUTOMATIC_CHECK_THROTTLED").put("latestAvailabilityConfirmed",false);
        return update;
    }

    private synchronized void finishScan(String run,String ownPackage,ScanReport value,boolean completed,RemediationAction verify) {
        if(!run.equals(flow.runId())) return;
        if(cancelled.get()) value.add(new Finding("scan.cancelled","검사 범위","사용자가 중단한 검사",Finding.Status.UNKNOWN,
                "중단 요청 이전에 완료한 관측만 표시합니다. 전체 검사를 완료한 결과가 아닙니다.","다시 점검을 누르면 처음부터 수집합니다."));
        if(verify!=null&&verify.kind!=RemediationAction.Kind.UNINSTALL) {
            Finding after=null;for(Finding f:value.findings) if(f.id.equals(verify.findingId)) { after=f;break; }
            String outcome=cancelled.get()?"VERIFICATION_UNAVAILABLE":RemediationRules.reobservedOutcome(verify.findingId,verify.beforeStatus,after);
            logRemediation(verify.id(),outcome,"재검사 결과: "+(after==null?"직접 확인할 수 없는 조치":after.status.name())
                    +". 현재 프로필의 노출된 범위만 확인합니다.");
        }
        Set<String> eligible=new HashSet<>();
        for(int i=0;i<value.inventory.length();i++) {
            JSONObject row=value.inventory.optJSONObject(i);
            if(row!=null&&RemediationController.canRemove(row,ownPackage)) eligible.add(row.optString("packageName"));
        }
        int manual=0;
        for(Finding finding:value.findings) if(finding.status==Finding.Status.WARN||finding.status==Finding.Status.ALERT) {
            if(!finding.id.startsWith("malware.app.")||!eligible.contains(finding.id.substring("malware.app.".length()))) manual++;
        }
        flow.automaticMode(automaticRemovalPrompts);
        flow.scanFinished(eligible,manual,value.count(Finding.Status.UNKNOWN),completed&&!cancelled.get(),System.currentTimeMillis());
        value.completedAt=System.currentTimeMillis();report=value;running=false;
        refreshStage();writeEvidence();announce();
    }

    private static boolean wifiAvailable(Context context) {
        try {
            android.net.ConnectivityManager manager=(android.net.ConnectivityManager)context.getSystemService(Context.CONNECTIVITY_SERVICE);
            android.net.Network network=manager==null?null:manager.getActiveNetwork();
            android.net.NetworkCapabilities caps=network==null?null:manager.getNetworkCapabilities(network);
            return caps!=null&&caps.hasTransport(android.net.NetworkCapabilities.TRANSPORT_WIFI);
        } catch(RuntimeException error) { return false; }
    }
    void catalogUpdatePreferenceChanged() { lastAutomaticCheckElapsed=0; }
    synchronized void updateCatalog(Context context,android.net.Uri selectedFile) {
        if(running||remediationBusy||catalogBusy||pendingRemediation!=null) return;
        final AtomicBoolean operationCancelled=new AtomicBoolean(false);
        catalogCancellation=operationCancelled;
        catalogBusy=true;catalogMessage=selectedFile==null?"검사 자료를 다운로드하고 서명을 확인하는 중입니다.":"선택한 검사 자료의 서명을 확인하는 중입니다.";
        announce();Context app=context.getApplicationContext();
        worker.execute(() -> {
            boolean updated=false;JSONObject diagnostics=null;
            try {
                CatalogUpdateManager.Result result;
                if(selectedFile==null) result=CatalogUpdateManager.downloadAndInstall(app,operationCancelled);
                else try(java.io.InputStream stream=app.getContentResolver().openInputStream(selectedFile)) {
                    if(stream==null) throw new java.io.IOException("선택한 파일을 열 수 없습니다.");
                    result=CatalogUpdateManager.importUpdate(app,stream,operationCancelled);
                }
                catalogMessage=result.message;diagnostics=result.diagnostics();updated=true;
                lastAutomaticCheckElapsed=Math.max(1,android.os.SystemClock.elapsedRealtime());
            } catch(Exception error) {
                catalogMessage="자료를 적용하지 않았습니다. 기존 자료를 유지합니다. "+error.getClass().getSimpleName()+": "+error.getMessage();
            }
            final boolean success=updated;final JSONObject update=diagnostics;
            main.post(() -> {
                synchronized(ScanSession.this) {
                    catalogBusy=false;catalogCancellation=null;refreshStage();
                    if(operationCancelled.get()) {
                        catalogMessage=success?"검사 자료 확인은 끝났지만 이어지는 점검은 중단했습니다. 새 점검을 누르면 현재 자료로 시작합니다.":
                                "검사 자료 확인을 중단했습니다. 새 점검을 누르기 전에는 자동 검사를 재개하지 않습니다.";
                        logRemediation("CATALOG_UPDATE","UPDATE_CANCELLED",catalogMessage);announce();
                    }
                    else if(success) { skipNextCatalogCheck=true;nextCatalogUpdateAttempt=update;startOneRun(app); }
                    else announce();
                }
            });
        });
    }

    synchronized void cancel() {
        if(catalogCancellation!=null) catalogCancellation.set(true);
        cancelled.set(true);automaticPromptsPaused=true;flow.cancel(System.currentTimeMillis());
        stage=running||remediationBusy||catalogBusy?"검사 중단 처리 중":"사용자가 점검을 중단했습니다";
        writeEvidence();announce();
    }
    synchronized void returnedFromRemediation(Context context) {
        final RemediationAction action=pendingRemediation;
        if(action==null||!leftForRemediation) return;
        final String run=flow.runId();pendingRemediation=null;leftForRemediation=false;remediationBusy=true;
        flow.verificationStarted(action.kind==RemediationAction.Kind.UNINSTALL?"앱 제거 결과 확인":"설정 화면 복귀 확인");
        logRemediation(action.id(),"SCREEN_RETURNED","화면에서 돌아왔습니다. 화면을 연 사실만으로 조치 완료를 판단하지 않습니다.");
        refreshStage();writeEvidence();announce();Context app=context.getApplicationContext();
        worker.execute(() -> {
            final String observed=action.kind==RemediationAction.Kind.UNINSTALL?
                    RemediationController.removalOutcome(app,action.packageName):"";
            main.post(() -> {
                synchronized(ScanSession.this) {
                    if(!run.equals(flow.runId())) return;
                    remediationBusy=false;
                    if(action.kind==RemediationAction.Kind.UNINSTALL) {
                        String detail="패키지 "+action.packageName+"의 현재 프로필 표시 여부를 재조회했습니다. 다른 프로필·잔존 코드·기기 전체 복구는 검증하지 않습니다.";
                        flow.removalObserved(action.packageName,observed,detail,System.currentTimeMillis());
                        logRemediation(action.id(),observed,detail);
                        if(!"PACKAGE_NOT_PRESENT".equals(observed)) blockAutomaticRemoval(action.packageName,
                                "앱 제거가 확인되지 않았습니다. 삭제를 취소했거나 관리자 권한 등의 제한이 있을 수 있습니다. 자동 삭제 안내를 멈췄습니다. 앱 설정과 기기 관리자 상태를 확인하세요.");
                    }
                    if(cancelled.get()) { refreshStage();writeEvidence();announce();return; }
                    // Every next target still needs a fresh authenticated live preflight.
                    if(action.kind==RemediationAction.Kind.UNINSTALL&&nextAutomaticRemoval(app.getPackageName())!=null) {
                        refreshStage();writeEvidence();announce();return;
                    }
                    startScan(app,true,action);
                }
            });
        });
    }
    synchronized JSONObject nextAutomaticRemoval(String ownPackage) {
        if(!automaticRemovalPrompts||automaticPromptsPaused||running||remediationBusy||catalogBusy
                ||pendingRemediation!=null||report==null||cancelled.get()||!flow.mayAdvanceAutomatically()) return null;
        for(int i=0;i<report.inventory.length();i++) {
            JSONObject row=report.inventory.optJSONObject(i);
            if(row!=null&&!automaticAttempts.contains(row.optString("packageName"))&&RemediationController.canRemove(row,ownPackage)) return row;
        }
        return null;
    }
    synchronized void attemptedRemoval(String packageName) {
        if(packageName==null||packageName.isEmpty()||cancelled.get()) return;
        automaticAttempts.add(packageName);flow.attempted(packageName);writeEvidence();
    }
    synchronized void removalPreflightStarted(RemediationAction action) {
        if(action==null||action.kind!=RemediationAction.Kind.UNINSTALL||cancelled.get()) return;
        remediationBusy=true;
        attemptedRemoval(action.packageName);flow.preflightStarted(action.packageName,"삭제 직전 현재 APK 재검증");
        refreshStage();writeEvidence();announce();
    }
    synchronized void removalPromptOpened(RemediationAction action) {
        if(action==null) return;
        flow.promptOpened(action.kind==RemediationAction.Kind.UNINSTALL?"Android 삭제 승인 대기":action.label());
        refreshStage();writeEvidence();announce();
    }
    synchronized void removalLaunchFailed(RemediationAction action,String detail) {
        remediationBusy=false;if(action==null) return;
        if(action.kind==RemediationAction.Kind.UNINSTALL) blockAutomaticRemoval(action.packageName,detail);
        else { flow.pause(detail,"",System.currentTimeMillis());refreshStage();writeEvidence();announce(); }
    }
    synchronized void deferRemovalUntilForeground(String pkg) {
        remediationBusy=false;flow.automaticMode(automaticRemovalPrompts);
        if(!cancelled.get()) {
            if(automaticPromptsPaused&&!flow.isHardPaused()) flow.pause(blockedRemovalDetail,"",System.currentTimeMillis());
            if(flow.deferUntilForeground(pkg)) automaticAttempts.remove(pkg);
            else {
                automaticPromptsPaused=true;
                blockedRemovalDetail=flow.snapshot().optString("statusDetail");
            }
        }
        refreshStage();writeEvidence();announce();
    }
    synchronized void pauseAutomaticRemoval(String reason) {
        automaticPromptsPaused=true;blockedRemovalDetail=reason==null?"":reason;
        flow.automaticMode(automaticRemovalPrompts);flow.pause(blockedRemovalDetail,"",System.currentTimeMillis());
        refreshStage();writeEvidence();announce();
    }
    synchronized void blockAutomaticRemoval(String packageName,String detail) {
        automaticPromptsPaused=true;blockedRemovalPackage=packageName==null?"":packageName;blockedRemovalDetail=detail==null?"":detail;
        flow.pause(blockedRemovalDetail,blockedRemovalPackage,System.currentTimeMillis());
        refreshStage();writeEvidence();announce();
    }
    synchronized JSONObject flowSnapshot() {
        flow.automaticMode(automaticRemovalPrompts);JSONObject snapshot=flow.snapshot();
        try { snapshot.put("catalogUpdateCancellationRequested",catalogCancellation!=null&&catalogCancellation.get()); }
        catch(Exception ignored) { }
        return snapshot;
    }
    synchronized void logRemediation(String action,String outcome,String detail) {
        JSONObject value=new JSONObject();
        try { value.put("time",System.currentTimeMillis()).put("runId",flow.runId())
                .put("action",action).put("outcome",outcome).put("detail",detail);remediationLog.put(value); }
        catch(Exception ignored) { }
        writeEvidence();
    }
    synchronized JSONArray logSnapshot() {
        try { return new JSONArray(remediationLog.toString()); }
        catch(Exception ignored) { return new JSONArray(); }
    }
    private void refreshStage() {
        if(cancelled.get()) { stage=running||remediationBusy||catalogBusy?"검사 중단 처리 중":"중단된 범위까지 결과 표시";return; }
        JSONObject snapshot=flow.snapshot();String phase=snapshot.optString("phase");
        if("COMPLETE".equals(phase)) stage="한 번에 점검 완료";
        else if("PAUSED".equals(phase)) stage=snapshot.optBoolean("foregroundDeferred")?"앱 화면 복귀 대기":"자동 조치 일시 정지 · 직접 확인 필요";
        else stage=snapshot.optString("lastActionLabel","점검 중");
    }
    private void writeEvidence() {
        if(report==null) return;
        try { report.evidence.put("oneRun",flowSnapshot()).put("remediationLog",logSnapshot())
                .put("catalogUpdateAttempt",copyObject(catalogUpdateAttempt)).put("cancelRequested",cancelled.get())
                .put("postResetRemovalMode",automaticRemovalPrompts).put("silentRemoval",false)
                .put("systemRemovalApprovalRequired",true); }
        catch(Exception ignored) { }
    }
    private static JSONObject copyObject(JSONObject value) {
        try { return value==null?new JSONObject():new JSONObject(value.toString()); }
        catch(Exception ignored) { return new JSONObject(); }
    }
}
