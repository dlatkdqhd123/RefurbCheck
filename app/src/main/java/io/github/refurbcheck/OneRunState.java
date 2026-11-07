package io.github.refurbcheck;

import java.util.Collection;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import org.json.JSONObject;

/**
 * Bookkeeping for one launch-to-summary cycle. This class grants no permission
 * to remove an app: the current scan, authenticated catalog, live Android
 * preflight and system confirmation remain separate mandatory gates.
 */
final class OneRunState {
    enum Phase { IDLE, UPDATING, SCANNING, PREPARING_REMOVAL, AWAITING_APPROVAL,
        VERIFYING_REMOVAL, RECHECKING, COMPLETE, PAUSED, CANCELLED }

    private Phase phase=Phase.IDLE;
    private String runId="",networkUpdateState="NOT_CHECKED",lastActionLabel="",statusDetail="";
    private long startedAt,finishedAt;
    private boolean initialScanComplete,recheckPerformed,scanInProgress,recheckInProgress;
    private boolean cancelled,hardPaused,foregroundDeferred,automaticMode=true,finalRecheckRequired;
    private int scanCount,manualReviewCount,unknownCount,latestEligibleCount;
    private final Set<String> eligibleSeen=new HashSet<>(),remaining=new HashSet<>();
    private final Set<String> attempts=new HashSet<>(),attemptsSeen=new HashSet<>();
    private final Set<String> removed=new HashSet<>(),blocked=new HashSet<>();

    synchronized void begin(long now,boolean automatic) {
        runId=UUID.randomUUID().toString();startedAt=now;finishedAt=0;phase=Phase.UPDATING;
        networkUpdateState="NOT_CHECKED";lastActionLabel="검사 자료 업데이트 확인";statusDetail="";
        initialScanComplete=false;recheckPerformed=false;scanInProgress=false;recheckInProgress=false;
        cancelled=false;hardPaused=false;foregroundDeferred=false;automaticMode=automatic;finalRecheckRequired=false;
        scanCount=0;manualReviewCount=0;unknownCount=0;latestEligibleCount=0;
        eligibleSeen.clear();remaining.clear();attempts.clear();attemptsSeen.clear();removed.clear();blocked.clear();
    }

    synchronized String runId() { return runId; }
    synchronized boolean isCancelled() { return cancelled; }
    synchronized boolean isHardPaused() { return hardPaused; }
    synchronized boolean mayAdvanceAutomatically() {
        return !runId.isEmpty()&&!cancelled&&!hardPaused&&automaticMode;
    }
    synchronized boolean hasPendingAutomaticWork() {
        return mayAdvanceAutomatically()&&(foregroundDeferred||phase==Phase.PREPARING_REMOVAL
                ||phase==Phase.AWAITING_APPROVAL||phase==Phase.VERIFYING_REMOVAL||phase==Phase.RECHECKING);
    }
    synchronized boolean needsFinalRecheck() { return finalRecheckRequired&&!cancelled&&!scanInProgress; }
    synchronized void automaticMode(boolean enabled) { automaticMode=enabled; }
    synchronized void updateFinished(String state) {
        networkUpdateState=state==null||state.isEmpty()?"UPDATE_STATE_UNAVAILABLE":state;
    }

    synchronized boolean scanStarted(boolean recheck) {
        if(runId.isEmpty()||cancelled||scanInProgress) return false;
        scanInProgress=true;recheckInProgress=recheck;scanCount++;finishedAt=0;foregroundDeferred=false;
        phase=recheck?Phase.RECHECKING:Phase.SCANNING;
        lastActionLabel=recheck?"조치 후 전체 재검사":"전체 점검";
        return true;
    }

    synchronized void scanFinished(Collection<String> candidates,int manual,int unknown,boolean completed,long now) {
        boolean wasRecheck=recheckInProgress;
        scanInProgress=false;recheckInProgress=false;
        remaining.clear();
        if(candidates!=null) for(String pkg:candidates) if(nonempty(pkg)) remaining.add(pkg);
        latestEligibleCount=remaining.size();eligibleSeen.addAll(remaining);
        manualReviewCount=Math.max(0,manual);unknownCount=Math.max(0,unknown);
        if(completed&&!cancelled) {
            if(wasRecheck) { recheckPerformed=true;finalRecheckRequired=false; }
            else initialScanComplete=true;
        }
        if(cancelled) return;
        if(!completed) {
            pause("검사를 끝내지 못했습니다. 완료된 관측과 미확인 항목을 확인하세요.","",now);
            return;
        }
        settle(now);
    }

    synchronized void attempted(String pkg) {
        if(!nonempty(pkg)||cancelled) return;
        attempts.add(pkg);attemptsSeen.add(pkg);
    }

    synchronized void preflightStarted(String pkg,String label) {
        if(cancelled) return;
        attempted(pkg);foregroundDeferred=false;finishedAt=0;
        phase=Phase.PREPARING_REMOVAL;lastActionLabel=label==null?"삭제 직전 재검증":label;
    }

    synchronized void promptOpened(String label) {
        if(cancelled) return;
        foregroundDeferred=false;finishedAt=0;phase=Phase.AWAITING_APPROVAL;
        lastActionLabel=label==null?"Android 확인 대기":label;
        // Opening a screen is not a removal outcome and increments no success counter.
    }

    synchronized void verificationStarted(String label) {
        if(cancelled) return;
        foregroundDeferred=false;finishedAt=0;phase=Phase.VERIFYING_REMOVAL;
        lastActionLabel=label==null?"조치 결과 확인":label;
    }

    synchronized void removalObserved(String pkg,String outcome,String detail,long now) {
        if(!nonempty(pkg)) return;
        // Only an independent package-manager absence observation is a success.
        // A later scan may find this package again; never subtract historical
        // successes from that scan's pending targets.
        if("PACKAGE_NOT_PRESENT".equals(outcome)) {
            removed.add(pkg);remaining.remove(pkg);
        } else {
            blocked.add(pkg);hardPaused=true;
        }
        finalRecheckRequired=true;
        if(cancelled) return;
        lastActionLabel="앱 제거 여부 확인";statusDetail=detail==null?"":detail;
        settle(now);
    }

    synchronized boolean deferUntilForeground(String pkg) {
        if(cancelled||!nonempty(pkg)) return false;
        if(!mayAdvanceAutomatically()) {
            String retry="화면을 벗어나 수동 삭제 확인을 멈췄습니다. 앱 화면에서 해당 항목을 다시 선택하면 새로 검증합니다.";
            if(!statusDetail.contains(retry)) statusDetail=(statusDetail.isEmpty()?"":statusDetail+" ")+retry;
            pause(statusDetail,"",System.currentTimeMillis());
            return false;
        }
        attempts.remove(pkg);foregroundDeferred=true;finishedAt=0;phase=Phase.PAUSED;
        lastActionLabel="앱 화면 복귀 대기";
        statusDetail="앱 화면이 다시 보이면 현재 파일을 다시 검증한 뒤 Android 확인창을 엽니다.";
        return true;
    }

    synchronized void pause(String reason,String pkg,long now) {
        if(nonempty(pkg)) blocked.add(pkg);
        hardPaused=true;foregroundDeferred=false;
        if(cancelled) return;
        phase=Phase.PAUSED;finishedAt=now;lastActionLabel="자동 조치 일시 정지";
        statusDetail=reason==null?"":reason;
    }

    synchronized void cancel(long now) {
        if(runId.isEmpty()) return;
        cancelled=true;foregroundDeferred=false;phase=Phase.CANCELLED;finishedAt=now;
        lastActionLabel="사용자가 중단함";statusDetail="이 실행의 자동 조치를 중단했습니다. 확인되지 않은 항목은 해결된 것으로 처리하지 않습니다.";
    }

    private void settle(long now) {
        if(cancelled) return;
        if(hardPaused) {
            phase=Phase.PAUSED;finishedAt=now;return;
        }
        if(!remaining.isEmpty()) {
            if(!automaticMode) {
                pause("자동 삭제 안내가 꺼져 있습니다. 남은 항목은 직접 확인하세요.","",now);return;
            }
            for(String pkg:remaining) if(!attempts.contains(pkg)) {
                phase=Phase.PREPARING_REMOVAL;finishedAt=0;lastActionLabel="검출 앱 삭제 준비";return;
            }
            pause("삭제를 시도한 앱이 아직 확인됩니다. 자동 반복을 멈추고 직접 확인을 기다립니다.","",now);
            return;
        }
        if(finalRecheckRequired) {
            phase=Phase.RECHECKING;finishedAt=0;lastActionLabel="조치 후 전체 재검사 준비";return;
        }
        phase=Phase.COMPLETE;finishedAt=now;lastActionLabel="한 번에 점검 완료";
        statusDetail="자동으로 수행 가능한 절차가 끝났습니다. 남은 확인 사항과 미검증 범위는 별도로 확인하세요.";
    }

    synchronized JSONObject snapshot() {
        JSONObject value=new JSONObject();
        try {
            value.put("schema","refurbcheck-one-run-v1").put("phase",phase.name()).put("stageNumber",stageNumber())
                    .put("runId",runId).put("startedAt",startedAt).put("finishedAt",finishedAt)
                    .put("initialScanComplete",initialScanComplete).put("recheckPerformed",recheckPerformed)
                    .put("scanCount",scanCount).put("scanInProgress",scanInProgress)
                    .put("eligibleCount",eligibleSeen.size()).put("latestEligibleCount",latestEligibleCount)
                    .put("remainingRemovalCount",remaining.size()).put("attemptedCount",attemptsSeen.size())
                    .put("removedCount",removed.size()).put("blockedCount",blocked.size())
                    .put("paused",!cancelled&&(hardPaused||foregroundDeferred)).put("cancelled",cancelled)
                    .put("cancellationRequested",cancelled).put("foregroundDeferred",foregroundDeferred)
                    .put("finalRecheckRequired",finalRecheckRequired).put("automaticRemovalEnabled",automaticMode)
                    .put("manualReviewCount",manualReviewCount+((hardPaused||cancelled)?remaining.size():0))
                    .put("unknownCount",unknownCount).put("networkUpdateState",networkUpdateState)
                    .put("lastActionLabel",lastActionLabel).put("statusDetail",statusDetail)
                    .put("factoryOriginalVerified",false).put("malwareAbsenceVerified",false)
                    .put("physicalHardwareVerified",false).put("allRequiredDomainsVerified",false)
                    .put("silentRemoval",false).put("systemRemovalApprovalRequired",true)
                    .put("removalCountScope","unique packages observed absent in the current Android profile; not device-wide eradication")
                    .put("completionScope","workflow only; remaining findings and unknown domains are not resolved by completion");
        } catch(Exception ignored) { }
        return value;
    }

    private int stageNumber() {
        switch(phase) {
            case IDLE:case UPDATING:return 1;
            case SCANNING:return 2;
            case PREPARING_REMOVAL:case AWAITING_APPROVAL:case VERIFYING_REMOVAL:return 3;
            case RECHECKING:return 4;
            default:return 5;
        }
    }
    private static boolean nonempty(String value) { return value!=null&&!value.isEmpty(); }
}
