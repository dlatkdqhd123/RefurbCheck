package io.github.refurbcheck;

import java.util.Arrays;
import java.util.Collections;
import org.json.JSONObject;

/** Pure workflow tests: package names are bookkeeping only, never removal authorization. */
public final class OneRunStateTests {
    private static final String A="example.fixture.a",B="example.fixture.b";
    private static int scenarios,assertions,failures;
    private interface Checked { void run() throws Exception; }

    public static void main(String[] args) {
        scenario("idle has no security assurance or implicit active cycle",() -> {
            OneRunState state=new OneRunState();JSONObject s=state.snapshot();
            same("IDLE",s.getString("phase"));same("",s.getString("runId"));same(0,s.getInt("scanCount"));
            no(state.mayAdvanceAutomatically());assurance(s);
        });
        scenario("no eligible app completes from a single scan while unknowns remain visible",() -> {
            OneRunState state=new OneRunState();state.begin(100,true);String run=state.runId();
            state.updateFinished("NO_WIFI");yes(state.scanStarted(false));
            state.scanFinished(Collections.emptyList(),3,4,true,200);JSONObject s=state.snapshot();
            same("COMPLETE",s.getString("phase"));same(run,s.getString("runId"));same(1,s.getInt("scanCount"));
            yes(s.getBoolean("initialScanComplete"));no(s.getBoolean("recheckPerformed"));no(state.needsFinalRecheck());
            same(3,s.getInt("manualReviewCount"));same(4,s.getInt("unknownCount"));same("NO_WIFI",s.getString("networkUpdateState"));
            same(200L,s.getLong("finishedAt"));assurance(s);
        });
        scenario("eligible apps prevent completion before live preflight and system approval",() -> {
            OneRunState state=scanned(A,B);JSONObject s=state.snapshot();
            same("PREPARING_REMOVAL",s.getString("phase"));same(2,s.getInt("eligibleCount"));same(2,s.getInt("remainingRemovalCount"));
            same(0L,s.getLong("finishedAt"));
            state.preflightStarted(A,"preflight");state.promptOpened("approval");s=state.snapshot();
            same("AWAITING_APPROVAL",s.getString("phase"));same(0,s.getInt("removedCount"));
            same(2,s.getInt("remainingRemovalCount"));same(1,s.getInt("attemptedCount"));
        });
        scenario("two confirmed absences require a final rescan before completion",() -> {
            OneRunState state=scanned(A,B);state.preflightStarted(A,"preflight");state.promptOpened("approval");
            state.verificationStarted("verify");same("VERIFYING_REMOVAL",state.snapshot().getString("phase"));
            state.removalObserved(A,"PACKAGE_NOT_PRESENT","current profile",300);
            same("PREPARING_REMOVAL",state.snapshot().getString("phase"));same(1,state.snapshot().getInt("removedCount"));
            state.preflightStarted(B,"preflight");state.promptOpened("approval");state.verificationStarted("verify");
            state.removalObserved(B,"PACKAGE_NOT_PRESENT","current profile",400);JSONObject s=state.snapshot();
            same("RECHECKING",s.getString("phase"));same(2,s.getInt("removedCount"));same(0,s.getInt("remainingRemovalCount"));
            same(0L,s.getLong("finishedAt"));yes(state.needsFinalRecheck());yes(state.scanStarted(true));
            state.scanFinished(Collections.emptyList(),1,5,true,500);s=state.snapshot();
            same("COMPLETE",s.getString("phase"));same(2,s.getInt("scanCount"));yes(s.getBoolean("recheckPerformed"));
            no(state.needsFinalRecheck());same(2,s.getInt("removedCount"));same(2,s.getInt("eligibleCount"));assurance(s);
        });
        scenario("duplicate callbacks never double count an absent package",() -> {
            OneRunState state=scanned(A);state.attempted(A);state.attempted(A);
            state.removalObserved(A,"PACKAGE_NOT_PRESENT","first",300);state.removalObserved(A,"PACKAGE_NOT_PRESENT","duplicate",301);
            same(1,state.snapshot().getInt("attemptedCount"));same(1,state.snapshot().getInt("removedCount"));
            same("RECHECKING",state.snapshot().getString("phase"));
        });
        scenario("cancelled or blocked uninstall is not a successful removal",() -> {
            for(String outcome:new String[]{"PACKAGE_STILL_PRESENT","VERIFICATION_UNAVAILABLE","SCREEN_OPENED","OPEN_FAILED",""}) {
                OneRunState state=scanned(A,B);state.preflightStarted(A,"preflight");state.promptOpened("approval");
                state.removalObserved(A,outcome,"not confirmed",300);JSONObject s=state.snapshot();
                same("PAUSED",s.getString("phase"));same(0,s.getInt("removedCount"));same(1,s.getInt("blockedCount"));
                same(2,s.getInt("remainingRemovalCount"));no(state.mayAdvanceAutomatically());yes(state.needsFinalRecheck());
                yes(state.scanStarted(true));state.scanFinished(Arrays.asList(A,B),0,1,true,400);
                same("PAUSED",state.snapshot().getString("phase"));yes(state.snapshot().getBoolean("recheckPerformed"));
            }
        });
        scenario("preflight failure leaves pending work and cannot manufacture a success",() -> {
            OneRunState state=scanned(A);state.preflightStarted(A,"preflight");state.pause("file changed",A,300);
            state.pause("duplicate failure",A,301);JSONObject s=state.snapshot();
            same("PAUSED",s.getString("phase"));same(1,s.getInt("blockedCount"));same(1,s.getInt("remainingRemovalCount"));
            same(0,s.getInt("removedCount"));no(state.mayAdvanceAutomatically());no(state.deferUntilForeground(A));
        });
        scenario("foreground return retries validation without reusing approval or a new run",() -> {
            OneRunState state=scanned(A);String run=state.runId();state.preflightStarted(A,"preflight");
            yes(state.deferUntilForeground(A));JSONObject s=state.snapshot();
            same("PAUSED",s.getString("phase"));yes(s.getBoolean("foregroundDeferred"));yes(s.getBoolean("paused"));
            yes(state.mayAdvanceAutomatically());same(0,s.getInt("removedCount"));same(0,s.getInt("blockedCount"));
            state.preflightStarted(A,"fresh preflight");s=state.snapshot();
            same(run,s.getString("runId"));same("PREPARING_REMOVAL",s.getString("phase"));
            no(s.getBoolean("foregroundDeferred"));no(s.getBoolean("paused"));same(1,s.getInt("attemptedCount"));
        });
        scenario("foreground deferral never revives policy-disabled automatic removal",() -> {
            OneRunState state=scanned(A);state.preflightStarted(A,"preflight");state.automaticMode(false);
            state.pause("mode off","",300);no(state.deferUntilForeground(A));no(state.mayAdvanceAutomatically());
            state.automaticMode(true);no(state.mayAdvanceAutomatically());same("PAUSED",state.snapshot().getString("phase"));
            state.begin(400,true);yes(state.mayAdvanceAutomatically());same("UPDATING",state.snapshot().getString("phase"));
        });
        scenario("manual preflight leaving the foreground pauses without an automatic retry",() -> {
            OneRunState state=scanned(A);state.automaticMode(false);state.pause("original policy reason","",300);
            state.preflightStarted(A,"explicit manual retry");same("PREPARING_REMOVAL",state.snapshot().getString("phase"));
            no(state.deferUntilForeground(A));JSONObject s=state.snapshot();same("PAUSED",s.getString("phase"));
            yes(s.getBoolean("paused"));no(s.getBoolean("foregroundDeferred"));no(state.mayAdvanceAutomatically());
            yes(s.getString("statusDetail").contains("original policy reason"));
            same(0,s.getInt("removedCount"));same(0,s.getInt("blockedCount"));
        });
        scenario("launcher guard preserves pending automatic work but permits stopped cycles to restart",() -> {
            OneRunState state=scanned(A);yes(state.hasPendingAutomaticWork());
            state.preflightStarted(A,"preflight");yes(state.hasPendingAutomaticWork());
            yes(state.deferUntilForeground(A));yes(state.hasPendingAutomaticWork());
            state.preflightStarted(A,"fresh preflight");state.promptOpened("approval");yes(state.hasPendingAutomaticWork());
            state.verificationStarted("verify");yes(state.hasPendingAutomaticWork());
            state.removalObserved(A,"PACKAGE_NOT_PRESENT","observed",300);yes(state.hasPendingAutomaticWork());
            yes(state.scanStarted(true));state.scanFinished(Collections.emptyList(),0,0,true,400);
            no(state.hasPendingAutomaticWork());
            state=scanned(A);state.cancel(300);no(state.hasPendingAutomaticWork());
            state=scanned(A);state.pause("failure",A,300);no(state.hasPendingAutomaticWork());
            state=scanned(A);state.automaticMode(false);no(state.hasPendingAutomaticWork());
        });
        scenario("stop during update prevents scan start and late callbacks from reopening the flow",() -> {
            OneRunState state=new OneRunState();state.begin(100,true);String run=state.runId();state.cancel(110);
            state.updateFinished("INSTALLED");no(state.scanStarted(false));state.preflightStarted(A,"late");state.promptOpened("late");
            state.verificationStarted("late");no(state.deferUntilForeground(A));
            JSONObject s=state.snapshot();same("CANCELLED",s.getString("phase"));same(run,s.getString("runId"));
            yes(s.getBoolean("cancelled"));yes(s.getBoolean("cancellationRequested"));same(0,s.getInt("scanCount"));
            same(0,s.getInt("removedCount"));same(0,s.getInt("attemptedCount"));same(110L,s.getLong("finishedAt"));
        });
        scenario("stop during scan remains stopped when scan results arrive",() -> {
            OneRunState state=new OneRunState();state.begin(100,true);yes(state.scanStarted(false));state.cancel(150);
            state.scanFinished(Arrays.asList(A),2,3,true,200);JSONObject s=state.snapshot();
            same("CANCELLED",s.getString("phase"));no(s.getBoolean("initialScanComplete"));no(s.getBoolean("scanInProgress"));
            same(1,s.getInt("remainingRemovalCount"));same(0,s.getInt("removedCount"));no(state.mayAdvanceAutomatically());
        });
        scenario("stop during preflight blocks approval transition and foreground retry",() -> {
            OneRunState state=scanned(A);state.preflightStarted(A,"preflight");state.cancel(250);
            state.promptOpened("late successful preflight");no(state.deferUntilForeground(A));state.pause("late failure",A,260);
            JSONObject s=state.snapshot();same("CANCELLED",s.getString("phase"));same(0,s.getInt("removedCount"));
            yes(s.getBoolean("cancellationRequested"));no(state.mayAdvanceAutomatically());no(state.scanStarted(true));
        });
        scenario("stop after system prompt may record observed absence without resuming work",() -> {
            OneRunState state=scanned(A,B);state.preflightStarted(A,"preflight");state.promptOpened("approval");state.cancel(300);
            state.verificationStarted("return");state.removalObserved(A,"PACKAGE_NOT_PRESENT","read only verification",350);
            JSONObject s=state.snapshot();same("CANCELLED",s.getString("phase"));same(1,s.getInt("removedCount"));
            same(1,s.getInt("remainingRemovalCount"));no(state.mayAdvanceAutomatically());no(state.needsFinalRecheck());no(state.scanStarted(true));
        });
        scenario("a package reappearing in final scan cannot be hidden by historical removal count",() -> {
            OneRunState state=scanned(A);state.preflightStarted(A,"preflight");state.removalObserved(A,"PACKAGE_NOT_PRESENT","observed",300);
            yes(state.scanStarted(true));state.scanFinished(Arrays.asList(A),0,1,true,400);JSONObject s=state.snapshot();
            same("PAUSED",s.getString("phase"));same(1,s.getInt("removedCount"));same(1,s.getInt("remainingRemovalCount"));
            same(1,s.getInt("latestEligibleCount"));no(state.mayAdvanceAutomatically());
        });
        scenario("new eligible package during final scan returns to preflight rather than completes",() -> {
            OneRunState state=scanned(A);state.preflightStarted(A,"preflight");state.removalObserved(A,"PACKAGE_NOT_PRESENT","observed",300);
            yes(state.scanStarted(true));state.scanFinished(Arrays.asList(B),0,2,true,400);JSONObject s=state.snapshot();
            same("PREPARING_REMOVAL",s.getString("phase"));same(2,s.getInt("eligibleCount"));same(1,s.getInt("remainingRemovalCount"));
            same(0L,s.getLong("finishedAt"));yes(state.mayAdvanceAutomatically());
        });
        scenario("automatic mode off leaves eligible targets visibly unresolved",() -> {
            OneRunState state=new OneRunState();state.begin(100,false);yes(state.scanStarted(false));
            state.scanFinished(Arrays.asList(A),2,1,true,200);JSONObject s=state.snapshot();
            same("PAUSED",s.getString("phase"));same(1,s.getInt("remainingRemovalCount"));same(3,s.getInt("manualReviewCount"));
            no(state.mayAdvanceAutomatically());same(0,s.getInt("removedCount"));
        });
        scenario("settings return rechecks but screen opening itself never resolves an item",() -> {
            OneRunState state=scanned();state.promptOpened("settings");same(0,state.snapshot().getInt("removedCount"));
            state.verificationStarted("settings returned");yes(state.scanStarted(true));
            state.scanFinished(Collections.emptyList(),3,4,true,300);JSONObject s=state.snapshot();
            same("COMPLETE",s.getString("phase"));yes(s.getBoolean("recheckPerformed"));same(3,s.getInt("manualReviewCount"));
            same(4,s.getInt("unknownCount"));same(0,s.getInt("removedCount"));
        });
        scenario("scan failure cannot become a successful complete cycle",() -> {
            OneRunState state=new OneRunState();state.begin(100,true);yes(state.scanStarted(false));
            state.scanFinished(Collections.emptyList(),0,1,false,200);JSONObject s=state.snapshot();
            same("PAUSED",s.getString("phase"));no(s.getBoolean("initialScanComplete"));no(state.mayAdvanceAutomatically());
        });
        scenario("fresh cycle changes identity and resets only run-specific counters",() -> {
            OneRunState state=scanned(A,B);String old=state.runId();state.preflightStarted(A,"preflight");
            state.removalObserved(A,"PACKAGE_NOT_PRESENT","observed",300);state.pause("blocked",B,301);state.cancel(302);
            state.begin(400,false);JSONObject s=state.snapshot();no(old.equals(s.getString("runId")));
            same(400L,s.getLong("startedAt"));same(0L,s.getLong("finishedAt"));same(0,s.getInt("eligibleCount"));
            same(0,s.getInt("removedCount"));same(0,s.getInt("blockedCount"));same(0,s.getInt("attemptedCount"));
            same(0,s.getInt("scanCount"));no(s.getBoolean("cancelled"));no(s.getBoolean("paused"));no(s.getBoolean("automaticRemovalEnabled"));
        });
        scenario("snapshot mutation cannot alter run identity counters or assurance",() -> {
            OneRunState state=scanned(A);String id=state.runId();JSONObject detached=state.snapshot();
            detached.put("phase","COMPLETE").put("removedCount",99).put("runId","forged").put("factoryOriginalVerified",true);
            JSONObject actual=state.snapshot();same(id,actual.getString("runId"));same("PREPARING_REMOVAL",actual.getString("phase"));
            same(0,actual.getInt("removedCount"));assurance(actual);
        });
        System.out.println("OneRunStateTests: "+scenarios+" scenarios, "+assertions+" assertions, "+failures+" failures");
        if(failures!=0) System.exit(1);
    }

    private static OneRunState scanned(String... packages) {
        OneRunState state=new OneRunState();state.begin(100,true);yes(state.scanStarted(false));
        state.scanFinished(Arrays.asList(packages),0,0,true,200);return state;
    }
    private static void assurance(JSONObject s) throws Exception {
        no(s.getBoolean("factoryOriginalVerified"));no(s.getBoolean("malwareAbsenceVerified"));
        no(s.getBoolean("physicalHardwareVerified"));no(s.getBoolean("allRequiredDomainsVerified"));
        no(s.getBoolean("silentRemoval"));yes(s.getBoolean("systemRemovalApprovalRequired"));
    }
    private static void scenario(String name,Checked body) {
        scenarios++;try { body.run(); } catch(Throwable error) { failures++;System.err.println("FAIL "+name+": "+error); }
    }
    private static void yes(boolean value) { assertions++;if(!value) throw new AssertionError("expected true"); }
    private static void no(boolean value) { assertions++;if(value) throw new AssertionError("expected false"); }
    private static void same(Object expected,Object actual) {
        assertions++;if(!expected.equals(actual)) throw new AssertionError("expected "+expected+", got "+actual);
    }
}
